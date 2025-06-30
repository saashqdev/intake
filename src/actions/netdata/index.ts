'use server'

import { revalidatePath } from 'next/cache'

import { protectedClient } from '@/lib/safe-action'
import { extractSSHDetails } from '@/lib/ssh'
import { addInstallNetdataQueue } from '@/queues/netdata/install'
import { addUninstallNetdataQueue } from '@/queues/netdata/uninstall'

import { installNetdataSchema, uninstallNetdataSchema } from './validator'

export const installNetdataAction = protectedClient
  .metadata({
    actionName: 'installNetdataAction',
  })
  .schema(installNetdataSchema)
  .action(async ({ clientInput, ctx }) => {
    const { serverId } = clientInput
    const { payload, userTenant } = ctx

    // Fetch server details from the database
    const server = await payload.findByID({
      collection: 'servers',
      id: serverId,
      depth: 5,
    })

    // Set up SSH connection details
    const sshDetails = extractSSHDetails({ server })

    // Add the job to the queue instead of executing directly
    await addInstallNetdataQueue({
      sshDetails,
      serverDetails: {
        id: serverId,
      },
      tenant: {
        slug: userTenant.tenant.slug,
      },
    })

    // Refresh the server details page
    revalidatePath(`/servers/${serverId}?tab=monitoring`)

    return {
      success: true,
      message:
        'Netdata installation started. You can monitor progress in the server logs.',
    }
  })

export const uninstallNetdataAction = protectedClient
  .metadata({
    actionName: 'uninstallNetdataAction',
  })
  .schema(uninstallNetdataSchema)
  .action(async ({ clientInput, ctx }) => {
    const { serverId } = clientInput
    const { payload, userTenant } = ctx

    const serverDetails = await payload.findByID({
      collection: 'servers',
      id: serverId,
      depth: 10,
    })

    const sshDetails = extractSSHDetails({ server: serverDetails })
    const uninstallResponse = await addUninstallNetdataQueue({
      serverDetails: {
        id: serverId,
      },
      sshDetails,
      tenant: {
        slug: userTenant.tenant.slug,
      },
    })

    if (uninstallResponse.id) {
      return { success: true }
    }
  })
