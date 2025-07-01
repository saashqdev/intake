import configPromise from '@payload-config'
import axios from 'axios'
import { RequiredDataFromCollection, getPayload } from 'payload'

import { getQueue, getWorker } from '@/lib/bullmq'
import { INTAKE_CONFIG } from '@/lib/constants'
import { jobOptions, pub, queueConnection } from '@/lib/redis'
import { sendActionEvent } from '@/lib/sendEvent'
import { Server, SshKey, Tenant } from '@/payload-types'

class VpsCreationError extends Error {
  constructor(
    message: string,
    public details?: Record<string, unknown>,
  ) {
    super(message)
    this.name = 'VpsCreationError'
  }
}

interface CreateVpsQueueArgs {
  sshKeys: SshKey[]
  vps: {
    plan: string
    displayName: string
    image: {
      imageId: string
      priceId: string
    }
    product: {
      productId: string
      priceId: string
    }
    region: {
      code: string
      priceId: string
    }
    defaultUser: string
    rootPassword: number
    period: {
      months: number
      priceId: string
    }
    addOns?: {
      backup?: {}
      priceId?: string
    }
    estimatedCost: number
  }
  accountDetails: {
    id: string
    accessToken: string
  }
  tenant: Tenant
}

// Function to add a job to the create VPS queue
export const addCreateVpsQueue = async (data: CreateVpsQueueArgs) => {
  const QUEUE_NAME = `tenant-${data.tenant.slug}-create-vps`

  const createVpsQueue = getQueue({
    name: QUEUE_NAME,
    connection: queueConnection,
  })

  getWorker<CreateVpsQueueArgs>({
    name: QUEUE_NAME,
    processor: async job => {
      const { sshKeys, vps, accountDetails, tenant } = job.data
      const token = accountDetails.accessToken
      const jobId = job.id

      const payload = await getPayload({ config: configPromise })

      console.log(
        `[${jobId}] VPS creation worker started for tenant ${tenant.slug}`,
      )

      try {
        if (!vps.plan || !vps.displayName) {
          throw new VpsCreationError('VPS plan and display name are required')
        }

        // Step 1: Create VPS order
        const vpsData = {
          plan: vps.plan,
          userData: {
            image: vps.image,
            product: vps.product,
            displayName: vps.displayName,
            region: vps.region,
            card: '',
            defaultUser: vps.defaultUser,
            rootPassword: vps.rootPassword,
            period: vps.period,
            plan: vps.plan,
            addOns: vps.addOns || {},
          },
        }

        console.log(
          `[${jobId}] Creating VPS order with data:`,
          JSON.stringify(vpsData, null, 2),
        )

        const { data: createdVpsOrderRes } = await axios.post(
          `${INTAKE_CONFIG.URL}/api/vpsOrders`,
          vpsData,
          {
            headers: {
              Authorization: `${INTAKE_CONFIG.AUTH_SLUG} API-Key ${token}`,
            },
            timeout: 200000, // 2 mins of timeout!
          },
        )

        const { doc: createdVpsOrder } = createdVpsOrderRes

        console.log(`[${jobId}] VPS order created: ${createdVpsOrder}`)

        // Step 2: Create server record in Payload
        const serverData: RequiredDataFromCollection<Server> = {
          name: vps.displayName,
          description: '',
          ip: '0.0.0.0',
          port: 22,
          username: 'root',
          provider: 'intake',
          tenant: tenant.id,
          cloudProviderAccount: accountDetails.id,
          preferConnectionType: 'tailscale',
          intakeVpsDetails: {
            id: createdVpsOrder.id,
            instanceId: createdVpsOrder.instanceId,
            status: createdVpsOrder.instanceResponse.status as NonNullable<
              Server['intakeVpsDetails']
            >['status'],
          },
          hostname: createdVpsOrder?.instanceResponse?.name,
          cloudInitStatus: 'running',
        }

        const createdServer = await payload.create({
          collection: 'servers',
          data: serverData,
        })

        console.log(
          `[${jobId}] Server record created with ID: ${createdServer.id}`,
        )

        // Step 5: Improved polling for public IP
        // const pollForPublicIP = async () => {
        //   const maxAttempts = 10
        //   const delayMs = 30000
        //   let pollTimeout: NodeJS.Timeout | null = null

        //   try {
        //     for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        //       try {
        //         console.log(
        //           `[${jobId}] Checking instance status (attempt ${attempt}/${maxAttempts})`,
        //         )

        //         const { data: instanceStatusRes } = await axios.get(
        //           `${INTAKE_CONFIG.URL}/api/vpsOrders?where[instanceId][equals]=${createdVpsOrder.instanceId}`,
        //           {
        //             headers: {
        //               Authorization: `${INTAKE_CONFIG.AUTH_SLUG} API-Key ${token}`,
        //             },
        //             timeout: 10000,
        //           },
        //         )

        //         const orders = instanceStatusRes?.docs || []
        //         if (orders.length === 0) {
        //           console.log(
        //             `[${jobId}] No orders found for instance ${createdVpsOrder.instanceId}`,
        //           )
        //           continue
        //         }

        //         const order = orders[0]
        //         const newStatus = order.instanceResponse.status
        //         const newIp = order.instanceResponse?.ipConfig?.v4?.ip

        //         if (
        //           createdServer.intakeVpsDetails?.status !== newStatus ||
        //           createdServer.ip !== newIp
        //         ) {
        //           const updateData: any = {
        //             intakeVpsDetails: {
        //               ...createdServer.intakeVpsDetails,
        //               status: newStatus,
        //             },
        //           }

        //           if (newIp) updateData.ip = newIp

        //           await payload.update({
        //             collection: 'servers',
        //             id: createdServer.id,
        //             data: updateData,
        //           })

        //           console.log(
        //             `[${jobId}] Server updated - Status: ${newStatus}, IP: ${newIp || 'not assigned'}`,
        //           )

        //           sendActionEvent({
        //             pub,
        //             action: 'refresh',
        //             tenantSlug: tenant.slug,
        //           })

        //           if (newStatus === 'running' && newIp) {
        //             console.log(`[${jobId}] VPS is ready with IP: ${newIp}`)
        //             return { ip: newIp, status: newStatus }
        //           }
        //         }

        //         if (order.status === 'failed' || order.status === 'error') {
        //           throw new VpsCreationError(
        //             `VPS creation failed: ${order.message || 'No details provided'}`,
        //             { orderStatus: order.status },
        //           )
        //         }
        //       } catch (error) {
        //         console.error(
        //           `[${jobId}] Error checking instance status:`,
        //           error,
        //         )
        //       }

        //       await new Promise(resolve => {
        //         pollTimeout = setTimeout(resolve, delayMs)
        //       })
        //     }

        //     throw new VpsCreationError(
        //       'VPS did not get a public IP within the expected time',
        //     )
        //   } finally {
        //     if (pollTimeout) clearTimeout(pollTimeout)
        //   }
        // }

        // const pollResult = await pollForPublicIP()

        sendActionEvent({
          pub,
          action: 'redirect',
          tenantSlug: tenant.slug,
          url: `/${tenant.slug}/servers/${createdServer.id}`,
        })

        return {
          success: true,
          orderId: createdVpsOrder.id,
          serverId: createdServer.id,
          // ip: pollResult.ip,
        }
      } catch (error) {
        console.error(`[${jobId}] VPS creation failed:`, error)

        sendActionEvent({
          pub,
          action: 'redirect',
          tenantSlug: tenant.slug,
          url: `/${tenant.slug}/servers`,
        })

        if (error instanceof VpsCreationError) {
          throw error
        }

        throw new VpsCreationError(
          'VPS creation failed: ' +
            (error instanceof Error ? error.message : 'Unknown error'),
          { originalError: error },
        )
      }
    },
    connection: queueConnection,
  })

  const id = `create-vps:${new Date().getTime()}`

  return await createVpsQueue.add(id, data, {
    jobId: id,
    ...jobOptions,
  })
}
