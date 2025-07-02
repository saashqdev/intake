import LayoutClient from '../../layout.client'

import { getINTakePlansAction, getIntakeUser } from '@/actions/cloud/inTake'
import { getAddServerDetails } from '@/actions/pages/server'
import ServerForm from '@/components/servers/ServerForm'

const SuspendedAddNewServerPage = async () => {
  const result = await getAddServerDetails()
  const inTakeDetails = await getIntakeUser()
  const vpsPlans = await getINTakePlansAction()

  const sshKeys = result?.data?.sshKeys ?? []
  const securityGroups = result?.data?.securityGroups ?? []

  return (
    <>
      <ServerForm
        sshKeys={sshKeys}
        securityGroups={securityGroups}
        inTakeAccounts={
          inTakeDetails?.data?.account ? [inTakeDetails?.data?.account] : []
        }
        vpsPlans={vpsPlans?.data ?? []}
        inTakeUser={inTakeDetails?.data?.user}
        formType='create'
      />

      {/* <IntakeCloudDrawer /> Dave commented */}
    </>
  )
}

const AddNewServerPage = async () => {
  return (
    <LayoutClient>
      <SuspendedAddNewServerPage />
    </LayoutClient>
  )
}

export default AddNewServerPage
