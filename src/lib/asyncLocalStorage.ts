import type { ILogtailLog } from '@logtail/types'
import { AsyncLocalStorage } from 'node:async_hooks'

export const asyncLocalStorage = new AsyncLocalStorage<{
  logger: ILogtailLog
}>()
