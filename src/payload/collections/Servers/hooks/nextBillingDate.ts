import { CollectionAfterReadHook } from 'payload'

import { INTAKE_CONFIG } from '@/lib/constants'
import { Server } from '@/payload-types'

export const nextBillingDateAfterRead: CollectionAfterReadHook<
  Server
> = async ({ doc, req, context }) => {
  const { payload } = req
  const { checkIntakeNextBillingDate } = context
  const instanceId = doc?.intakeVpsDetails?.instanceId

  if (doc.provider !== 'intake' || !checkIntakeNextBillingDate || !instanceId) {
    return doc
  }

  const existingBillingDate = doc?.intakeVpsDetails?.next_billing_date
    ? new Date(doc.intakeVpsDetails.next_billing_date)
    : null
  const now = new Date()

  const isMissing = !existingBillingDate
  const isExpired = existingBillingDate && existingBillingDate < now
  if (!isMissing && !isExpired) {
    return doc
  }

  let token: string | undefined
  try {
    if (typeof doc.cloudProviderAccount === 'object') {
      token = doc.cloudProviderAccount?.inTakeDetails?.accessToken
    } else {
      const { inTakeDetails } = await payload.findByID({
        collection: 'cloudProviderAccounts',
        id: doc.cloudProviderAccount ?? '',
      })

      token = inTakeDetails?.accessToken
    }
    const res = await fetch(
      `${INTAKE_CONFIG.URL}/api/vpsOrders?pagination=false&where[or][0][and][0][instanceId][equals]=${instanceId}`,
      {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `users API-Key ${token}`,
        },
      },
    )
    const data = await res.json()
    const externalOrder = Array.isArray(data) ? data[0] : data

    if (!externalOrder?.docs?.at(0)?.next_billing_date) return doc
    const updatedNextBillingDate = new Date(
      externalOrder?.docs?.at(0)?.next_billing_date,
    ).toISOString()

    // ✅ Use payload.update instead of calling payload
    await payload.update({
      collection: 'servers',
      id: doc.id,
      data: {
        intakeVpsDetails: {
          next_billing_date: updatedNextBillingDate,
        },
      },
    })

    if (!doc.intakeVpsDetails) {
      doc.intakeVpsDetails = {}
    }

    doc.intakeVpsDetails.next_billing_date = updatedNextBillingDate
  } catch (err) {
    console.error(
      `Error updating nextBillingDate for instanceId ${instanceId}:`,
      err,
    )
  }

  return doc
}
