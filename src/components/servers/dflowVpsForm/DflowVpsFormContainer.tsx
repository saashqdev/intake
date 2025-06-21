'use client'

import { useState } from 'react'

import { VpsPlan } from '@/actions/cloud/inTake/types'
import { CloudProviderAccount, SshKey } from '@/payload-types'

import { AccountConnectionStatus } from './AccountConnectionStatus'
import { AccountSelectionSection } from './AccountSelectionSection'
import { HeaderSection } from './HeaderSection'
import { IntakeVpsFormProvider } from './IntakeVpsFormProvider'
import { OrderForm } from './OrderForm'
import { PaymentStatusSection } from './PaymentStatusSection'
import { SpecificationsSection } from './SpecificationsSection'
import { TrafficSection } from './TrafficSection'

export const IntakeVpsFormContainer = ({
  vpsPlan,
  inTakeAccounts,
  selectedINTakeAccount,
  sshKeys,
  inTakeUser,
}: {
  vpsPlan: VpsPlan
  inTakeAccounts?: CloudProviderAccount[]
  selectedINTakeAccount?: CloudProviderAccount
  sshKeys: SshKey[]
  inTakeUser: any
}) => {
  const [selectedAccount, setSelectedAccount] = useState<{
    id: string
    token: string
  }>({
    id: inTakeAccounts?.[0]?.id || '',
    token: inTakeAccounts?.[0]?.inTakeDetails?.accessToken || '',
  })

  return (
    <IntakeVpsFormProvider
      vpsPlan={vpsPlan}
      sshKeys={sshKeys}
      selectedAccount={selectedAccount}
      onAccountChange={setSelectedAccount}>
      <div className='space-y-6'>
        <HeaderSection vpsPlan={vpsPlan} />
        <AccountSelectionSection
          inTakeAccounts={inTakeAccounts}
          selectedAccount={selectedAccount}
          onAccountChange={setSelectedAccount}
        />
        <div className='space-y-3'>
          <AccountConnectionStatus />
          <PaymentStatusSection />
        </div>
        <SpecificationsSection vpsPlan={vpsPlan} />
        <TrafficSection vpsPlan={vpsPlan} />
        <OrderForm inTakeUser={inTakeUser} />
      </div>
    </IntakeVpsFormProvider>
  )
}
