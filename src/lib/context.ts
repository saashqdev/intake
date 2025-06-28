import { AsyncLocalStorage } from 'async_hooks'

type RequestContext = {
  requestId?: string
  user?: { id: string; email: string }
}

export const asyncContext = new AsyncLocalStorage<RequestContext>()

export const withContext = (ctx: RequestContext, fn: () => void) => {
  asyncContext.run(ctx, fn)
}

export const getContext = () => asyncContext.getStore()
