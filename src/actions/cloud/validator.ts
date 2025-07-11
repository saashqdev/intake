import { z } from 'zod'

export const cloudProviderAccountsSchema = z.object({
  type: z.enum(['aws', 'azure', 'digitalocean', 'gcp', 'inTake']),
})

export const syncIntakeServersSchema = z.object({
  id: z.string(),
})

export const getVpsOrderByInstanceIdSchema = z.object({
  instanceId: z.number().min(1),
})
