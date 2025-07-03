import { CollectionAfterChangeHook } from 'payload'

import traefik from '@/lib/axios/traefik'
import { Service } from '@/payload-types'

export const handleTraefikConfiguration: CollectionAfterChangeHook<
  Service
> = async ({ doc, req, operation, previousDoc }) => {
  const { payload } = req

  // Skipping traefik configuration for databases
  if (doc.type === 'database') {
    return doc
  }

  // ? creating traefik configuration during server creation time
  if (operation === 'create') {
    const { server } = await payload.findByID({
      collection: 'projects',
      id: typeof doc.project === 'object' ? doc.project.id : doc.project,
      depth: 10,
    })

    if (typeof server === 'object') {
      const tenantSlug =
        typeof server.tenant === 'object' ? server.tenant?.slug : ''

      try {
        const response = await traefik.post('/configuration', {
          username: tenantSlug,
          serviceName: doc.name,
          tls: false,
          targetIP: server.tailscalePrivateIp,
          serverName: server.hostname,
        })

        console.log(response.data)
      } catch (error) {
        console.dir(
          { message: 'Failed to create traefik configuration', error },
          { depth: null },
        )
      }
    }
  }

  // handling deletion of traefik configuration during service deletion
  else if (operation === 'update' && doc.deletedAt && !previousDoc.deletedAt) {
    const { server } = await payload.findByID({
      collection: 'projects',
      id: typeof doc.project === 'object' ? doc.project.id : doc.project,
      depth: 10,
    })

    if (typeof server === 'object') {
      const tenantSlug =
        typeof server.tenant === 'object' ? server.tenant?.slug : ''

      try {
        const response = await traefik.delete('/configuration', {
          data: {
            username: tenantSlug,
            serviceName: doc.name,
            serverName: server.hostname,
          },
        })

        console.log(response.data)
      } catch (error) {
        console.dir(
          { message: 'Failed to delete traefik configuration', error },
          { depth: null },
        )
      }
    }
  }
}
