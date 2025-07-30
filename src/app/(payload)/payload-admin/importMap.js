import { default as default_fb905ece0654b411a3f8da7cbe8baa1d } from '@/components/ImpersonateUser'
import { BulkDeleteButton as BulkDeleteButton_dbef22401404dda2caddfae892201948, BulkRestoreButton as BulkRestoreButton_dbef22401404dda2caddfae892201948, BulkSoftDeleteButton as BulkSoftDeleteButton_dbef22401404dda2caddfae892201948, DeleteButton as DeleteButton_dbef22401404dda2caddfae892201948, RestoreButton as RestoreButton_dbef22401404dda2caddfae892201948, SoftDeleteButton as SoftDeleteButton_dbef22401404dda2caddfae892201948, ToggleButton as ToggleButton_dbef22401404dda2caddfae892201948, VisibilityChecker as VisibilityChecker_dbef22401404dda2caddfae892201948 } from '@payload-bites/soft-delete/client'
import { SoftDeleteProviderRsc as SoftDeleteProviderRsc_c45c4f8d9ba288d17e180b40027d3024 } from '@payload-bites/soft-delete/rsc'
import { TenantField as TenantField_1d0591e3cf4f332c83a86da13a0de59a, TenantSelector as TenantSelector_1d0591e3cf4f332c83a86da13a0de59a, WatchTenantCollection as WatchTenantCollection_1d0591e3cf4f332c83a86da13a0de59a } from '@payloadcms/plugin-multi-tenant/client'
import { TenantSelectionProvider as TenantSelectionProvider_d6d5f193a167989e2ee7d14202901e62 } from '@payloadcms/plugin-multi-tenant/rsc'
import { JSONField as JSONField_3817bf644402e67bfe6577f60ef982de, TextareaField as TextareaField_3817bf644402e67bfe6577f60ef982de, TextField as TextField_3817bf644402e67bfe6577f60ef982de } from '@payloadcms/ui'
import { default as default_fb905ece0654b411a3f8da7cbe8baa1d } from '@/components/ImpersonateUser'

export const importMap = {
  '@payload-bites/soft-delete/client#RestoreButton':
    RestoreButton_dbef22401404dda2caddfae892201948,
  '@payload-bites/soft-delete/client#SoftDeleteButton':
    SoftDeleteButton_dbef22401404dda2caddfae892201948,
  '@payload-bites/soft-delete/client#DeleteButton':
    DeleteButton_dbef22401404dda2caddfae892201948,
  '@payload-bites/soft-delete/client#VisibilityChecker':
    VisibilityChecker_dbef22401404dda2caddfae892201948,
  '@payload-bites/soft-delete/client#ToggleButton':
    ToggleButton_dbef22401404dda2caddfae892201948,
  '@payload-bites/soft-delete/client#BulkSoftDeleteButton':
    BulkSoftDeleteButton_dbef22401404dda2caddfae892201948,
  '@payload-bites/soft-delete/client#BulkDeleteButton':
    BulkDeleteButton_dbef22401404dda2caddfae892201948,
  '@payload-bites/soft-delete/client#BulkRestoreButton':
    BulkRestoreButton_dbef22401404dda2caddfae892201948,
  '@/components/ImpersonateUser#default':
    default_fb905ece0654b411a3f8da7cbe8baa1d,
  '@payloadcms/plugin-multi-tenant/client#TenantField':
    TenantField_1d0591e3cf4f332c83a86da13a0de59a,
  '@payloadcms/ui#TextField': TextField_3817bf644402e67bfe6577f60ef982de,
  '@payloadcms/ui#JSONField': JSONField_3817bf644402e67bfe6577f60ef982de,
  '@payloadcms/ui#TextareaField':
    TextareaField_3817bf644402e67bfe6577f60ef982de,
  '@payloadcms/plugin-multi-tenant/client#WatchTenantCollection':
    WatchTenantCollection_1d0591e3cf4f332c83a86da13a0de59a,
  '@payloadcms/plugin-multi-tenant/client#TenantSelector':
    TenantSelector_1d0591e3cf4f332c83a86da13a0de59a,
  '@payloadcms/plugin-multi-tenant/rsc#TenantSelectionProvider':
    TenantSelectionProvider_d6d5f193a167989e2ee7d14202901e62,
  '@payload-bites/soft-delete/rsc#SoftDeleteProviderRsc':
    SoftDeleteProviderRsc_c45c4f8d9ba288d17e180b40027d3024,
}
