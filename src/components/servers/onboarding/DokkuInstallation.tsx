'use client'

import { Hammer, HardDrive, Plug2 } from 'lucide-react'
import { useAction } from 'next-safe-action/hooks'
import { useEffect, useMemo } from 'react'

import { getUserAction } from '@/actions/auth'
import TimeLineComponent, {
  TimeLineComponentType,
} from '@/components/TimeLineComponent'
import { Dokku } from '@/components/icons'
import { useDokkuInstallationStep } from '@/components/onboarding/dokkuInstallation/DokkuInstallationStepContext'
import Step1 from '@/components/onboarding/dokkuInstallation/Step1'
import Step2 from '@/components/onboarding/dokkuInstallation/Step2'
import Step3 from '@/components/onboarding/dokkuInstallation/Step3'
import Step4 from '@/components/onboarding/dokkuInstallation/Step4'
import { ServerType } from '@/payload-types-overrides'

import ServerOnboardingLayout from './ServerOnboardingLayout'

const DokkuInstallation = ({ server }: { server: ServerType }) => {
  const { dokkuInstallationStep, isDokkuInstallationStepsComplete } =
    useDokkuInstallationStep()

  const {
    execute: getUser,
    result: { data: user },
  } = useAction(getUserAction)

  useEffect(() => {
    getUser()
  }, [])

  const list = useMemo<TimeLineComponentType[]>(() => {
    return [
      {
        title: 'Server Preparation',
        description: `Preparing ${server.name || 'your server'} for Dokku installation`,
        content: <Step1 server={server as ServerType} />,
        icon: <HardDrive size={16} />,
        highlighted: dokkuInstallationStep > 1,
      },
      {
        title: 'Dokku Installation',
        description: `Installing Dokku PaaS platform on ${server.provider === 'aws' ? 'EC2 instance' : 'server'}`,
        content: <Step2 server={server} />,
        icon: <Dokku fontSize={16} />,
        disabled: dokkuInstallationStep < 2,
        highlighted: dokkuInstallationStep > 2,
      },
      {
        title: 'Essential Plugins',
        description: 'Installing required plugins for seamless app deployment',
        content: <Step3 server={server} />,
        icon: <Plug2 size={20} />,
        disabled: dokkuInstallationStep < 3,
        highlighted: dokkuInstallationStep > 3,
      },
      {
        title: 'Build Tools Setup',
        description:
          'Configuring build environment for application deployments',
        content: <Step4 server={server} />,
        icon: <Hammer size={20} />,
        disabled: dokkuInstallationStep < 4,
      },
    ]
  }, [dokkuInstallationStep, server])

  // Check if Dokku is properly installed on this server
  const installationDone =
    !!server && !!server.version && server.version !== 'not-installed'

  // Check if required plugins are installed on this server
  const pluginsInstalled = (server?.plugins ?? []).find(
    plugin => plugin.name === 'letsencrypt',
  )

  // Check if SSL email configuration is completed for this server
  const emailConfirmationDone =
    pluginsInstalled &&
    pluginsInstalled.configuration &&
    typeof pluginsInstalled.configuration === 'object' &&
    !Array.isArray(pluginsInstalled.configuration) &&
    pluginsInstalled.configuration.email

  // Server onboarding is complete when all components are properly configured
  const isServerOnboardingComplete =
    installationDone &&
    Boolean(pluginsInstalled) &&
    Boolean(emailConfirmationDone)

  const getCardTitle = () => {
    const serverIdentifier =
      server.name || `${server.provider?.toUpperCase()} Server`
    return `Setting up ${serverIdentifier} for Deployment`
  }

  return (
    <ServerOnboardingLayout
      server={server}
      cardTitle={getCardTitle()}
      disableNextStep={
        !isServerOnboardingComplete || !isDokkuInstallationStepsComplete
      }>
      <TimeLineComponent list={list} />
    </ServerOnboardingLayout>
  )
}

export default DokkuInstallation
