import { ArrowUpRight } from 'lucide-react'
import Image from 'next/image'
import Link from 'next/link'
import { redirect } from 'next/navigation'
import React, { Suspense } from 'react'

import { getIntakeUser } from '@/actions/cloud/inTake'
import { getGithubStarsAction } from '@/actions/github'
import Banner from '@/components/Banner'
import DocSidebar from '@/components/DocSidebar'
import Logo from '@/components/Logo'
import ToggleTheme from '@/components/ToggleTheme'
import { Github } from '@/components/icons'
import { NavUser } from '@/components/nav-user'
import { NavUserSkeleton } from '@/components/skeletons/DashboardLayoutSkeleton'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { getCurrentUser } from '@/lib/getCurrentUser'
import Provider from '@/providers/Provider'

interface PageProps {
  params: Promise<{
    organisation: string
  }>
  children: React.ReactNode
}

const NavUserSuspended = async () => {
  const user = await getCurrentUser()

  if (!user) {
    redirect('/sign-in')
  }

  return <NavUser user={user} />
}

const DashboardLayoutInner = async ({
  params,
}: {
  params: PageProps['params']
}) => {
  const result = await getGithubStarsAction()
  const intakeUser = await getIntakeUser()
  const hasClaimedCredits = intakeUser?.data?.user?.hasClaimedFreeCredits
  const organisationSlug = (await params).organisation

  return (
    <div className='sticky top-0 z-50 w-full bg-background'>
      <div className='mx-auto flex w-full max-w-6xl items-center justify-between p-4'>
        <div className='flex min-h-9 items-center gap-2 text-2xl font-semibold'>
          <Link
            href={`/${organisationSlug}/dashboard`}
            className='flex items-center gap-1'>
            <Logo showText />
          </Link>

          {/* Breadcrumb placeholders */}
          <div id='projectName' />
          <div id='serviceName' className='-ml-2' />
          <div id='serverName' className='-ml-4' />
        </div>

        <div className='flex items-center gap-x-4'>
          <Link
            target='_blank'
            rel='noopener noreferrer'
            className='hidden items-center gap-x-1 transition-colors duration-300 hover:text-muted-foreground md:inline-flex'
            href='https://github.com/akhil-naidu/intake'>
            <Github width='1.25em' height='1.25em' />{' '}
            {result?.data?.stars ? result?.data?.stars : 0}
          </Link>

          {!hasClaimedCredits && (
            <Dialog>
              <DialogTrigger asChild>
                <Button
                  variant={'ghost'}
                  size={'icon'}
                  className='hidden w-full p-1 md:block'>
                  <Image
                    src={'/images/gift.png'}
                    width={100}
                    height={100}
                    alt='gift-credits'
                    className='size-7'
                  />
                </Button>
              </DialogTrigger>

              <DialogContent>
                <div>
                  <Image
                    src={'/images/gift.png'}
                    width={100}
                    height={100}
                    alt='gift-credits'
                    className='mx-auto mb-2 size-14'
                  />
                  <DialogHeader>
                    <DialogTitle className='text-center text-xl'>
                      Claim your free credits!
                    </DialogTitle>
                    <DialogDescription className='mx-auto max-w-sm text-center'>
                      You can claim rewards by joining our Discord community.
                      Click on Claim Rewards to continue on{' '}
                      <a
                        className='inline-flex items-center text-foreground underline'
                        href='https://gointake.ca/dashboard'
                        target='_blank'
                        rel='noopener noreferrer'>
                        gointake.ca
                        <ArrowUpRight size={16} />
                      </a>
                    </DialogDescription>
                  </DialogHeader>
                </div>
              </DialogContent>
            </Dialog>
          )}

          <ToggleTheme />

          <Suspense fallback={<NavUserSkeleton />}>
            <NavUserSuspended />
          </Suspense>
        </div>
      </div>
    </div>
  )
}

const DashboardLayout = ({ children, params }: PageProps) => {
  return (
    <div className='relative flex h-screen w-full overflow-hidden'>
      <div className='flex-1 overflow-y-auto'>
        <DashboardLayoutInner params={params} />
        {children}
      </div>

      <DocSidebar />
    </div>
  )
}

export default async function OrganisationLayout({
  children,
  params,
}: PageProps) {
  return (
    <Provider>
      <Banner />
      <DashboardLayout params={params}>{children}</DashboardLayout>
    </Provider>
  )
}
