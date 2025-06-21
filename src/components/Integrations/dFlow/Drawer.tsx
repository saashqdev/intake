'use client'

import GithubIntegrationsLoading from '../GithubIntegrationsLoading'
import { Link } from 'lucide-react'
import { useAction } from 'next-safe-action/hooks'
import { parseAsString, useQueryState } from 'nuqs'
import { useEffect } from 'react'

import { getCloudProvidersAccountsAction } from '@/actions/cloud'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { integrationsList } from '@/lib/integrationList'

import INTakeForm from './Form'
import CloudProvidersList from './List'

const IntakeDrawer = () => {
  const [activeSlide, setActiveSlide] = useQueryState(
    'active',
    parseAsString.withDefault(''),
  )

  const integration = integrationsList.find(
    integration => integration.slug === 'intake',
  )

  const { execute, isPending, result } = useAction(
    getCloudProvidersAccountsAction,
  )

  useEffect(() => {
    if (activeSlide === 'intake' && !result?.data) {
      execute({ type: 'inTake' })
    }
  }, [activeSlide, result])

  const icon = integration ? (
    <div className='mb-2 flex size-14 items-center justify-center rounded-md border'>
      <div className='relative'>
        <integration.icon className='size-8 blur-lg saturate-200' />
        <integration.icon className='absolute inset-0 size-8' />
      </div>
    </div>
  ) : null

  // Count existing inTake accounts
  const intakeAccountsCount = result?.data?.length || 0
  const canAddNewAccount = intakeAccountsCount === 0

  return (
    <Sheet
      open={activeSlide === 'intake'}
      onOpenChange={state => {
        setActiveSlide(state ? 'intake' : '')
      }}>
      <SheetContent className='flex w-full flex-col justify-between sm:max-w-lg'>
        <SheetHeader className='text-left'>
          <SheetTitle className='flex w-full items-center gap-3 text-base'>
            {icon} Integration Settings
          </SheetTitle>

          <p className='pt-4 font-semibold'>{integration?.label}</p>
          <SheetDescription className='!mt-0'>
            {integration?.description}
          </SheetDescription>
        </SheetHeader>

        {isPending && <GithubIntegrationsLoading />}

        {!isPending && result.data && (
          <ScrollArea className='flex-grow'>
            <CloudProvidersList accounts={result.data} refetch={execute} />
          </ScrollArea>
        )}

        <SheetFooter>
          {canAddNewAccount ? (
            <INTakeForm
              refetch={execute}
              existingAccountsCount={intakeAccountsCount}>
              <Button>
                <Link />
                Connect account
              </Button>
            </INTakeForm>
          ) : (
            <div className='w-full text-center'>
              <p className='mb-2 text-sm text-muted-foreground'>
                You can only connect one inTake account
              </p>
              <Button disabled variant='outline' className='w-full'>
                <Link />
                Account limit reached
              </Button>
            </div>
          )}
        </SheetFooter>
      </SheetContent>
    </Sheet>
  )
}

export default IntakeDrawer
