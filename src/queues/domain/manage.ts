import { addUpdateEnvironmentVariablesQueue } from '../environment/update'
import configPromise from '@payload-config'
import { Job } from 'bullmq'
import { env } from 'env'
import { NodeSSH, SSHExecCommandResponse } from 'node-ssh'
import { getPayload } from 'payload'

import { getQueue, getWorker } from '@/lib/bullmq'
import { dokku } from '@/lib/dokku'
import { jobOptions, pub, queueConnection } from '@/lib/redis'
import { sendActionEvent, sendEvent } from '@/lib/sendEvent'
import { SSHType, dynamicSSH } from '@/lib/ssh'
import { Service } from '@/payload-types'

interface QueueArgs {
  sshDetails: SSHType
  serviceDetails: {
    action: 'add' | 'remove' | 'set'
    domain: string
    name: string
    certificateType: 'letsencrypt' | 'none'
    autoRegenerateSSL: boolean
    id: string
    variables: Service['variables']
  }
  serverDetails: {
    id: string
    hostname: string
  }
  updateEnvironmentVariables?: boolean
  tenantDetails: {
    slug: string
  }
}

const operation = {
  add: 'added',
  remove: 'removed',
  set: 'setted',
} as const

export const addManageServiceDomainQueue = async (data: QueueArgs) => {
  const QUEUE_NAME = `server-${data.serverDetails.id}-manage-service-domain`

  const manageServiceDomainQueue = getQueue({
    name: QUEUE_NAME,
    connection: queueConnection,
  })

  const worker = getWorker<QueueArgs>({
    name: QUEUE_NAME,
    processor: async job => {
      const {
        sshDetails,
        serverDetails,
        updateEnvironmentVariables = false,
        tenantDetails,
      } = job.data
      const {
        domain,
        name,
        action,
        certificateType,
        id: serviceId,
        variables,
      } = job.data.serviceDetails
      let ssh: NodeSSH | null = null
      const payload = await getPayload({ config: configPromise })

      try {
        ssh = await dynamicSSH(sshDetails)

        let executionResponse: SSHExecCommandResponse = {
          code: -1,
          signal: null,
          stdout: '',
          stderr: '',
        }

        switch (action) {
          case 'add':
            executionResponse = await dokku.domains.add(ssh, name, domain, {
              onStdout: async chunk => {
                console.info(chunk.toString())
                sendEvent({
                  pub,
                  message: chunk.toString(),
                  serverId: serverDetails.id,
                })
              },
              onStderr: async chunk => {
                console.info({
                  addGlobalDomainLogs: {
                    message: chunk.toString(),
                    type: 'stdout',
                  },
                })
                sendEvent({
                  pub,
                  message: chunk.toString(),
                  serverId: serverDetails.id,
                })
              },
            })
            break
          case 'remove':
            executionResponse = await dokku.domains.remove(ssh, name, domain, {
              onStdout: async chunk => {
                console.info(chunk.toString())
                sendEvent({
                  pub,
                  message: chunk.toString(),
                  serverId: serverDetails.id,
                })
              },
              onStderr: async chunk => {
                console.info({
                  removeGlobalDomainLogs: {
                    message: chunk.toString(),
                    type: 'stdout',
                  },
                })
                sendEvent({
                  pub,
                  message: chunk.toString(),
                  serverId: serverDetails.id,
                })
              },
            })
            break
          case 'set':
            executionResponse = await dokku.domains.set(ssh, name, domain, {
              onStdout: async chunk => {
                console.info(chunk.toString())
                sendEvent({
                  pub,
                  message: chunk.toString(),
                  serverId: serverDetails.id,
                })
              },
              onStderr: async chunk => {
                console.info({
                  setGlobalDomainLogs: {
                    message: chunk.toString(),
                    type: 'stdout',
                  },
                })
                sendEvent({
                  pub,
                  message: chunk.toString(),
                  serverId: serverDetails.id,
                })
              },
            })
            break
          default:
            break
        }

        if (executionResponse.code === 0) {
          sendEvent({
            pub,
            message: `✅ Successfully ${operation[action]} domain ${domain}`,
            serverId: serverDetails.id,
          })

          const domains = await dokku.domains.list({ ssh, appName: name })

          try {
            const service = await payload.findByID({
              collection: 'services',
              id: serviceId,
            })

            const newDomains = (service.domains ?? []).map(domain => ({
              ...domain,
              synced: domains.includes(domain.domain),
            }))

            await payload.update({
              id: serviceId,
              collection: 'services',
              data: {
                domains: newDomains,
              },
            })

            sendActionEvent({
              pub,
              action: 'refresh',
              tenantSlug: tenantDetails.slug,
            })
          } catch (error) {
            let message = error instanceof Error ? error.message : ''

            console.log(
              `Service missing ${serviceId}, failed to update domain details: ${message}`,
            )
          }
        }

        if (certificateType === 'letsencrypt' && action !== 'remove') {
          sendEvent({
            pub,
            message: `Started adding SSL Certificate to domain ${domain}`,
            serverId: serverDetails.id,
          })

          // check domains before removing wildcard-domain
          const domainsList = await dokku.domains.list({
            ssh,
            appName: name,
          })

          const wildcardDomainExists = domainsList.some(domain =>
            domain.endsWith(env.NEXT_PUBLIC_PROXY_DOMAIN_URL ?? ' '),
          )

          // skipping letsencrypt enablement when there is single proxy domain
          if (wildcardDomainExists && domainsList.length === 1) {
            sendEvent({
              pub,
              message: `🔁 Skipping regenerated SSL certificates for service: ${name}`,
              serverId: serverDetails.id,
            })

            return
          }

          // remove the wildcard-domain before generating letsencrypt
          if (env.NEXT_PUBLIC_PROXY_DOMAIN_URL && serverDetails.hostname) {
            const domain = `${name}.${serverDetails.hostname}.${env.NEXT_PUBLIC_PROXY_DOMAIN_URL}`
            const removeResponse = await dokku.domains.remove(ssh, name, domain)

            console.dir({ removeResponse }, { depth: null })
          }

          const letsencryptResponse = await dokku.letsencrypt.enable(
            ssh,
            name,
            {
              onStdout: async chunk => {
                console.info(chunk.toString())
                sendEvent({
                  pub,
                  message: chunk.toString(),
                  serverId: serverDetails.id,
                })
              },
              onStderr: async chunk => {
                console.info({
                  setGlobalDomainLogs: {
                    message: chunk.toString(),
                    type: 'stdout',
                  },
                })
                sendEvent({
                  pub,
                  message: chunk.toString(),
                  serverId: serverDetails.id,
                })
              },
            },
          )

          if (letsencryptResponse.code === 0) {
            sendEvent({
              pub,
              message: `✅ Successfully added SSL Certificate to domain ${domain}`,
              serverId: serverDetails.id,
            })
          }

          // add the wildcard-domain after generating letsencrypt
          if (env.NEXT_PUBLIC_PROXY_DOMAIN_URL && serverDetails.hostname) {
            const domain = `${name}.${serverDetails.hostname}.${env.NEXT_PUBLIC_PROXY_DOMAIN_URL}`
            const addResponse = await dokku.domains.add(ssh, name, domain)

            console.dir({ addResponse }, { depth: null })
          }
        }

        if (updateEnvironmentVariables) {
          addUpdateEnvironmentVariablesQueue({
            sshDetails,
            serverDetails,
            serviceDetails: {
              id: serviceId,
              name,
              noRestart: false,
              previousVariables: [],
              variables: variables ?? [],
            },
            tenantDetails,
          })
        }
      } catch (error) {
        let message = error instanceof Error ? error.message : ''
        throw new Error(
          `❌ Failed ${operation[action]} domain ${domain}: ${message}`,
        )
      } finally {
        ssh?.dispose()
      }
    },
    connection: queueConnection,
  })

  worker.on('failed', async (job: Job<QueueArgs> | undefined, err) => {
    if (job?.data) {
      sendEvent({
        pub,
        message: err.message,
        serverId: job.data.serverDetails.id,
      })
    }
  })

  const id = `manage-domain-${data.serviceDetails.domain}:${new Date().getTime()}`

  return await manageServiceDomainQueue.add(id, data, {
    ...jobOptions,
    jobId: id,
  })
}
