import { Job } from 'bullmq'
import { NodeSSH } from 'node-ssh'

import { getQueue, getWorker } from '@/lib/bullmq'
import { dokku } from '@/lib/dokku'
import { jobOptions, pub, queueConnection } from '@/lib/redis'
import { sendEvent } from '@/lib/sendEvent'
import { SSHType, dynamicSSH } from '@/lib/ssh'

interface QueueArgs {
  sshDetails: SSHType
  serviceDetails: {
    id: string
    name: string
  }
  serverDetails: {
    id: string
  }
}

export const addRestartAppQueue = async (data: QueueArgs) => {
  const QUEUE_NAME = `server-${data?.serverDetails?.id}-restart-app`

  const restartAppQueue = getQueue({
    name: QUEUE_NAME,
    connection: queueConnection,
  })

  const worker = getWorker<QueueArgs>({
    name: QUEUE_NAME,
    processor: async job => {
      const { sshDetails, serviceDetails, serverDetails } = job.data
      let ssh: NodeSSH | null = null

      console.log(`starting restartApp queue for ${serviceDetails.name}`)

      try {
        ssh = await dynamicSSH(sshDetails)
        const res = await dokku.process.restart(ssh, serviceDetails.name, {
          onStdout: async chunk => {
            sendEvent({
              pub,
              message: chunk.toString(),
              serverId: serverDetails.id,
            })
          },
          onStderr: async chunk => {
            sendEvent({
              pub,
              message: chunk.toString(),
              serverId: serverDetails.id,
            })
          },
        })

        sendEvent({
          pub,
          message: `✅ Successfully restarted ${serviceDetails.name}`,
          serverId: serverDetails.id,
        })
      } catch (error) {
        let message = error instanceof Error ? error.message : ''
        throw new Error(
          `❌ Failed restarting ${serviceDetails?.name} : ${message}`,
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

  const id = `restart-${data.serviceDetails.name}:${new Date().getTime()}`

  return await restartAppQueue.add(id, data, {
    jobId: id,
    ...jobOptions,
  })
}
