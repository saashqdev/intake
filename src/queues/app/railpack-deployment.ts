import { dokku } from '../../lib/dokku'
import { SSHType, dynamicSSH } from '../../lib/ssh'
import configPromise from '@payload-config'
import { env } from 'env'
import { NodeSSH } from 'node-ssh'
import { getPayload } from 'payload'

import { getQueue, getWorker } from '@/lib/bullmq'
import { getBuildDetails } from '@/lib/getBuildDetails'
import { jobOptions, pub, queueConnection } from '@/lib/redis'
import { sendActionEvent, sendEvent } from '@/lib/sendEvent'
import { server } from '@/lib/server'
import { Service } from '@/payload-types'

interface QueueArgs {
  appName: string
  sshDetails: SSHType
  serviceDetails: {
    deploymentId: string
    serviceId: string
    provider: Service['provider']
    providerType: Service['providerType']
    githubSettings?: Service['githubSettings']
    azureSettings?: Service['azureSettings']
    giteaSettings?: Service['giteaSettings']
    variables: NonNullable<Service['variables']>
    populatedVariables: string
    serverId: string
    bitbucketSettings?: Service['bitbucketSettings']
    gitlabSettings?: Service['gitlabSettings']
  }
  tenantSlug: string
}

export const addRailpackDeployQueue = async (data: QueueArgs) => {
  const QUEUE_NAME = `server-${data.serviceDetails.serverId}-deploy-app-railpack`

  const railpackDeployQueue = getQueue({
    name: QUEUE_NAME,
    connection: queueConnection,
  })

  getWorker<QueueArgs>({
    name: QUEUE_NAME,
    connection: queueConnection,
    processor: async job => {
      const payload = await getPayload({ config: configPromise })
      let ssh: NodeSSH | null = null
      const { appName, sshDetails, serviceDetails, tenantSlug } = job.data
      const {
        serverId,
        serviceId,
        populatedVariables,
        provider,
        providerType,
        azureSettings,
        githubSettings,
        giteaSettings,
        bitbucketSettings,
        gitlabSettings,
      } = serviceDetails
      console.dir({ provider }, { depth: null })

      const formattedVariables = JSON.parse(populatedVariables)

      try {
        console.log('inside queue: ' + QUEUE_NAME)
        console.log('from queue', job.id)

        // updating the deployment status to building
        await payload.update({
          collection: 'deployments',
          id: serviceDetails.deploymentId,
          data: {
            status: 'building',
          },
        })

        sendActionEvent({
          pub,
          action: 'refresh',
          tenantSlug,
        })

        ssh = await dynamicSSH(sshDetails)
        const buildDetails = await getBuildDetails({
          providerType,
          azureSettings,
          githubSettings,
          giteaSettings,
          provider,
          bitbucketSettings,
          gitlabSettings,
        })

        // Step 1: Set dokku build-dir if buildPath is provided
        const buildPath = buildDetails.buildPath

        await dokku.builder.setBuildDir({
          ssh,
          appName,
          buildDir: buildPath,
        })

        sendEvent({
          message:
            buildPath && buildPath !== '/'
              ? `Set dokku build-dir to ${buildPath}`
              : `Reset dokku build-dir to default`,
          pub,
          serverId,
          serviceId,
          channelId: serviceDetails.deploymentId,
        })

        // Step 2: Setting dokku port
        const port = buildDetails.port ? buildDetails.port.toString() : '3000'

        // validate weather port is set or not
        const exposedPorts = (await dokku.ports.report(ssh, appName)) ?? []
        const hasPortExposed = exposedPorts?.includes(`http:80:${port}`)

        if (hasPortExposed) {
          sendEvent({
            message: `${port} already exposed skipping exposure!`,
            pub,
            serverId,
            serviceId,
            channelId: serviceDetails.deploymentId,
          })
        } else {
          sendEvent({
            message: `Stated exposing port ${port}`,
            pub,
            serverId,
            serviceId,
            channelId: serviceDetails.deploymentId,
          })

          const portResponse = await dokku.ports.set({
            ssh,
            appName,
            options: {
              onStdout: async chunk => {
                sendEvent({
                  message: chunk.toString(),
                  pub,
                  serverId,
                  serviceId,
                  channelId: serviceDetails.deploymentId,
                })
              },
              onStderr: async chunk => {
                sendEvent({
                  message: chunk.toString(),
                  pub,
                  serverId,
                  serviceId,
                  channelId: serviceDetails.deploymentId,
                })
              },
            },
            ports: [
              {
                scheme: 'http',
                host: '80',
                container: port,
              },
            ],
          })

          if (portResponse) {
            sendEvent({
              message: `✅ Successfully exposed port ${port}`,
              pub,
              serverId,
              serviceId,
              channelId: serviceDetails.deploymentId,
            })
          } else {
            sendEvent({
              message: `❌ Failed to exposed port ${port}`,
              pub,
              serverId,
              serviceId,
              channelId: serviceDetails.deploymentId,
            })
          }
        }

        // Step 3: Cloning the repo
        if (buildDetails.token) {
          // authenticating the git provider
          await dokku.git.auth({
            ssh,
            token: buildDetails.token,
            username: buildDetails.owner,
            hostname: buildDetails.hostname,
            options: {
              onStdout: async chunk => {
                sendEvent({
                  message: chunk.toString(),
                  pub,
                  serverId,
                  serviceId,
                  channelId: serviceDetails.deploymentId,
                })
              },
              onStderr: async chunk => {
                sendEvent({
                  message: chunk.toString(),
                  pub,
                  serverId,
                  serviceId,
                  channelId: serviceDetails.deploymentId,
                })
              },
            },
          })
        }

        sendEvent({
          message: `Stated cloning repository`,
          pub,
          serverId,
          serviceId,
          channelId: serviceDetails.deploymentId,
        })

        const cloningResponse = await dokku.git.sync({
          ssh,
          appName: appName,
          build: false,
          // if provider is given deploying from github-app else considering as public repository
          gitRepoUrl: buildDetails.url,
          branchName: buildDetails.branch,
          options: {
            onStdout: async chunk => {
              sendEvent({
                message: chunk.toString(),
                pub,
                serverId,
                serviceId,
                channelId: serviceDetails.deploymentId,
              })
            },
            onStderr: async chunk => {
              sendEvent({
                message: chunk.toString(),
                pub,
                serverId,
                serviceId,
                channelId: serviceDetails.deploymentId,
              })
            },
          },
        })

        if (cloningResponse.code === 0) {
          sendEvent({
            message: `✅ Successfully cloned repository`,
            pub,
            serverId,
            serviceId,
            channelId: serviceDetails.deploymentId,
          })
        } else {
          sendEvent({
            message: `❌ Failed to clone repository`,
            pub,
            serverId,
            serviceId,
            channelId: serviceDetails.deploymentId,
          })

          // exiting from the flow
          throw new Error('failed to clone repository')
        }

        // creating a workspace from bare repository
        sendEvent({
          message: `Started creating a git-workspace`,
          pub,
          serverId,
          serviceId,
          channelId: serviceDetails.deploymentId,
        })

        // Step 5: Creating a workspace from bare repository
        const workspaceResponse = await server.git.createWorkspace({
          appName,
          options: {
            onStdout: async chunk => {
              sendEvent({
                message: chunk.toString(),
                pub,
                serverId,
                serviceId,
                channelId: serviceDetails.deploymentId,
              })
            },
            onStderr: async chunk => {
              sendEvent({
                message: chunk.toString(),
                pub,
                serverId,
                serviceId,
                channelId: serviceDetails.deploymentId,
              })
            },
          },
          ssh,
        })

        console.log({ workspaceResponse })

        if (workspaceResponse.code === 0) {
          sendEvent({
            message: `✅ Successfully created workspace`,
            pub,
            serverId,
            serviceId,
            channelId: serviceDetails.deploymentId,
          })
        } else {
          throw new Error('❌ Failed to create workspace, please try again!')
        }

        // Step 6: Building the image with railpack
        const imageCreationResponse = await server.docker.createImage({
          appName,
          options: {
            onStdout: async chunk => {
              sendEvent({
                message: chunk.toString(),
                pub,
                serverId,
                serviceId,
                channelId: serviceDetails.deploymentId,
              })
            },
            onStderr: async chunk => {
              sendEvent({
                message: chunk.toString(),
                pub,
                serverId,
                serviceId,
                channelId: serviceDetails.deploymentId,
              })
            },
          },
          ssh,
          environmentVariables: formattedVariables,
          buildPath: buildPath === '/' ? undefined : buildPath,
        })

        if (imageCreationResponse.code === 0) {
          sendEvent({
            message: `✅ Successfully created docker-image`,
            pub,
            serverId,
            serviceId,
            channelId: serviceDetails.deploymentId,
          })
        } else {
          // Deleting the workspace if railpack image creation failed
          await server.git.deleteWorkspace({ appName, ssh })

          throw new Error('❌ Failed to create docker-image')
        }

        // Step 7: Deploying the docker image
        const deployImageResponse = await dokku.git.deployImage({
          ssh,
          appName,
          imageName: `${appName}-docker`,
          options: {
            onStdout: async chunk => {
              sendEvent({
                message: chunk.toString(),
                pub,
                serverId,
                serviceId,
                channelId: serviceDetails.deploymentId,
              })
            },
            onStderr: async chunk => {
              sendEvent({
                message: chunk.toString(),
                pub,
                serverId,
                serviceId,
                channelId: serviceDetails.deploymentId,
              })
            },
          },
        })

        console.log({ deployImageResponse })

        // Regardless of deployment status deleting the workspace
        await server.git.deleteWorkspace({ appName, ssh })

        if (deployImageResponse.code === 0) {
          sendEvent({
            message: `✅ Successfully deployed app`,
            pub,
            serverId,
            serviceId,
            channelId: serviceDetails.deploymentId,
          })
        } else {
          throw new Error('❌ Failed to deploy app')
        }

        // ? Step 7: Check for Let's Encrypt status & generate SSL only when NEXT_PUBLIC_PROXY_DOMAIN_URL is not attached
        if (!env.NEXT_PUBLIC_PROXY_DOMAIN_URL) {
          const letsencryptStatus = await dokku.letsencrypt.status({
            appName,
            ssh,
          })

          if (
            letsencryptStatus.code === 0 &&
            letsencryptStatus.stdout === 'true'
          ) {
            sendEvent({
              message: `✅ SSL enabled, skipping SSL generation`,
              pub,
              serverId,
              serviceId,
              channelId: serviceDetails.deploymentId,
            })
          } else {
            sendEvent({
              message: `Started generating SSL`,
              pub,
              serverId,
              serviceId,
              channelId: serviceDetails.deploymentId,
            })

            const letsencryptResponse = await dokku.letsencrypt.enable(
              ssh,
              appName,
              {
                onStdout: async chunk => {
                  sendEvent({
                    message: chunk.toString(),
                    pub,
                    serverId,
                    serviceId,
                    channelId: serviceDetails.deploymentId,
                  })
                },
                onStderr: async chunk => {
                  sendEvent({
                    message: chunk.toString(),
                    pub,
                    serverId,
                    serviceId,
                    channelId: serviceDetails.deploymentId,
                  })
                },
              },
            )

            if (letsencryptResponse.code === 0) {
              sendEvent({
                message: `✅ Successfully generated SSL certificates`,
                pub,
                serverId,
                serviceId,
                channelId: serviceDetails.deploymentId,
              })
            } else {
              sendEvent({
                message: `❌ Failed to generated SSL certificates`,
                pub,
                serverId,
                serviceId,
                channelId: serviceDetails.deploymentId,
              })
            }
          }
        }

        sendEvent({
          message: `Updating domain details...`,
          pub,
          serverId,
          serviceId,
        })

        // Step 9: updating the domain details
        const domainsResponse = await dokku.domains.report(ssh, appName)

        if (domainsResponse.length) {
          try {
            const { domains = [] } = await payload.findByID({
              id: serviceId,
              collection: 'services',
            })

            await payload.update({
              collection: 'services',
              id: serviceId,
              data: {
                domains: domainsResponse?.map(domain => {
                  const domainExists = domains?.find(
                    domainDetails => domainDetails.domain === domain,
                  )

                  if (domainExists) {
                    return {
                      ...domainExists,
                      synced: true,
                    }
                  }

                  return {
                    domain,
                    synced: true,
                  }
                }),
              },
            })

            sendEvent({
              message: `✅ Updated domain details`,
              pub,
              serverId,
              serviceId,
            })
          } catch (error) {
            const message = error instanceof Error ? error.message : ''
            sendEvent({
              message: `❌ Failed to update domain details: ${message}`,
              pub,
              serverId,
              serviceId,
            })
          }
        }

        // Step 10: saving the deployment logs
        const logs = (
          await pub.lrange(serviceDetails.deploymentId, 0, -1)
        ).reverse()

        await payload.update({
          collection: 'deployments',
          data: {
            status: 'success',
            logs,
          },
          id: serviceDetails.deploymentId,
        })

        sendActionEvent({
          pub,
          action: 'refresh',
          tenantSlug,
        })
      } catch (error) {
        let message = ''

        if (error instanceof Error) {
          message = error.message
        }

        sendEvent({
          message,
          pub,
          serverId,
          serviceId,
          channelId: serviceDetails.deploymentId,
        })

        const logs = (
          await pub.lrange(serviceDetails.deploymentId, 0, -1)
        ).reverse()

        await payload.update({
          collection: 'deployments',
          data: {
            status: 'failed',
            logs,
          },
          id: serviceDetails.deploymentId,
        })

        sendActionEvent({
          pub,
          action: 'refresh',
          tenantSlug,
        })
        throw new Error(`❌ Failed to deploy app: ${message}`)
      } finally {
        if (ssh) {
          ssh.dispose()
        }
      }
    },
  })

  // Create a unique job ID that prevents duplicates but allows identification
  const id = `railpack-deploy:${data.appName}:${Date.now()}`

  return await railpackDeployQueue.add(id, data, {
    ...jobOptions,
    jobId: id,
  })
}
