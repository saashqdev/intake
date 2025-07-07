import axios from 'axios'
import { CollectionAfterReadHook } from 'payload'

import { INTAKE_CONFIG } from '@/lib/constants'
import { Server } from '@/payload-types'

export const populateIntakeVpsDetails: CollectionAfterReadHook<
  Server
> = async ({ doc, req, context }) => {
  const { payload } = req

  console.log({
    Provider: doc.provider,
    intakeVpsDetails: doc.intakeVpsDetails,
    hostname: doc.hostname,
  })

  // Only proceed if provider is intake and intakeVpsDetails are empty
  if (
    doc.provider !== 'intake' ||
    (doc.intakeVpsDetails?.instanceId &&
      doc.intakeVpsDetails?.status &&
      doc.intakeVpsDetails.orderId) ||
    !doc.hostname
  ) {
    return doc
  }

  console.log('Populating intakeVpsDetails for server', doc.id)

  try {
    // Get the access token from the cloud provider account
    let token: string | undefined
    if (typeof doc.cloudProviderAccount === 'object') {
      token = doc.cloudProviderAccount?.inTakeDetails?.accessToken
    } else {
      const { inTakeDetails } = await payload.findByID({
        collection: 'cloudProviderAccounts',
        id: doc.cloudProviderAccount ?? '',
      })
      token = inTakeDetails?.accessToken
    }

    if (!token) {
      console.warn(`No access token found for server ${doc.id}`)
      return doc
    }

    // Fetch instance status using hostname (nested in instanceResponse.name)
    const { data: instanceStatusRes } = await axios.get(
      `${INTAKE_CONFIG.URL}/api/vpsOrders?where[instanceResponse.name][equals]=${doc.hostname}`,
      {
        headers: {
          Authorization: `${INTAKE_CONFIG.AUTH_SLUG} API-Key ${token}`,
        },
        timeout: 10000,
      },
    )

    // Check if we got a valid response with data
    if (
      !instanceStatusRes?.docs ||
      !Array.isArray(instanceStatusRes.docs) ||
      instanceStatusRes.docs.length === 0
    ) {
      console.warn(`No instance found for hostname ${doc.hostname}`)
      return doc
    }

    const instanceData = instanceStatusRes.docs[0]

    console.log(instanceData)

    // Extract relevant data from the instance based on the actual response structure
    const intakeVpsDetails = {
      orderId: instanceData.id || null, // The order ID is the document ID
      instanceId: instanceData.instanceId || null,
      status: instanceData.instanceResponse?.status || 'unknown', // Status is nested in instanceResponse
      next_billing_date: instanceData.next_billing_date
        ? new Date(instanceData.next_billing_date).toISOString()
        : null,
    }

    console.log({ intakeVpsDetails })

    // Update the server with the intakeVpsDetails
    await payload.update({
      collection: 'servers',
      id: doc.id,
      data: {
        intakeVpsDetails,
      },
    })

    // Update the doc object to reflect the changes
    doc.intakeVpsDetails = intakeVpsDetails

    console.log(
      `Successfully populated intakeVpsDetails for server ${doc.id} with hostname ${doc.hostname}`,
    )
  } catch (error) {
    console.error(
      `Error populating intakeVpsDetails for server ${doc.id} with hostname ${doc.hostname}:`,
      error,
    )
  }

  return doc
}
