'use client'

import SidebarToggleButton from '../../SidebarToggleButton'
import SecretContent from '../../ui/blur-reveal'
import { zodResolver } from '@hookform/resolvers/zod'
import { Workflow } from 'lucide-react'
import { useAction } from 'next-safe-action/hooks'
import { useParams } from 'next/navigation'
import { useForm } from 'react-hook-form'
import { toast } from 'sonner'
import { z } from 'zod'

import { updateServiceAction } from '@/actions/service'
import { updateServiceSchema } from '@/actions/service/validator'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { buildOptions } from '@/lib/buildOptions'
import { Service } from '@/payload-types'

const GiteaForm = ({ service }: { service: Service }) => {
  const params = useParams<{ id: string; serviceId: string }>()

  const form = useForm<z.infer<typeof updateServiceSchema>>({
    resolver: zodResolver(updateServiceSchema),
    defaultValues: {
      id: params.serviceId,
      providerType: 'gitea',
      builder: service?.builder ?? 'buildPacks',
      giteaSettings: {
        repository: service?.giteaSettings?.repository || '',
        branch: service?.giteaSettings?.branch || '',
        owner: service?.giteaSettings?.owner || '',
        gitToken: service?.giteaSettings?.gitToken || '',
        port: service?.giteaSettings?.port || 3000,
        buildPath: service?.giteaSettings?.buildPath || '/',
      },
    },
  })

  const { execute: saveServiceDetails, isPending } = useAction(
    updateServiceAction,
    {
      onSuccess: ({ data }) => {
        if (data) {
          toast.success(
            'Successfully updated, trigger deployment to apply changes!',
          )
        }
      },
      onError: ({ error }) => {
        toast.error(
          error?.serverError ||
            'Failed to update service details, please try again.',
        )
      },
    },
  )

  function onSubmit(values: z.infer<typeof updateServiceSchema>) {
    saveServiceDetails(values)
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className='w-full space-y-6'>
        <Alert variant='info'>
          <Workflow className='h-4 w-4' />

          <AlertTitle>Automatic deployments are coming soon!</AlertTitle>
          <AlertDescription>
            For now, you can set up your Gitea service with the following
            details. Make sure to trigger a deployment after saving the changes.
          </AlertDescription>
        </Alert>

        <div className='grid gap-4 md:grid-cols-2'>
          {/* Repository URL */}
          <FormField
            control={form.control}
            name='giteaSettings.repository'
            render={({ field }) => (
              <FormItem>
                <FormLabel>Repository URL</FormLabel>
                <FormControl>
                  <Input
                    type='text'
                    placeholder='ex: https://github.com/akhil-naidu/intake'
                    {...field}
                    value={field.value || ''}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          {/* Branch */}
          <FormField
            control={form.control}
            name='giteaSettings.branch'
            render={({ field }) => (
              <FormItem>
                <FormLabel>Branch</FormLabel>
                <FormControl>
                  <Input
                    type='text'
                    placeholder='ex: main or commit-hash: 6492769'
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          {/* Repository URL */}
          <FormField
            control={form.control}
            name='giteaSettings.owner'
            render={({ field }) => (
              <FormItem>
                <FormLabel>Username</FormLabel>
                <FormControl>
                  <Input
                    type='text'
                    placeholder='ex: your-username'
                    {...field}
                    value={field.value || ''}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          {/* Branch */}
          <FormField
            control={form.control}
            name='giteaSettings.gitToken'
            render={({ field }) => (
              <FormItem>
                <FormLabel>Git Token</FormLabel>
                <FormControl>
                  <SecretContent defaultHide={!!field.value}>
                    <Input type='text' {...field} />
                  </SecretContent>
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          {/* Port */}
          <FormField
            control={form.control}
            name='giteaSettings.port'
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Port
                  <SidebarToggleButton
                    directory='services'
                    fileName='app-service'
                    sectionId='#port--editable'
                  />
                </FormLabel>
                <FormControl>
                  <Input
                    type='number'
                    placeholder='ex: 3000'
                    {...field}
                    value={field.value || ''}
                    onChange={e => {
                      const value = e.target.value
                        ? parseInt(e.target.value, 10)
                        : ''
                      field.onChange(value)
                    }}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          {/* Build path */}
          <FormField
            control={form.control}
            name='giteaSettings.buildPath'
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Build path{' '}
                  <SidebarToggleButton
                    directory='services'
                    fileName='app-service'
                    sectionId='#build-path--editable'
                  />
                </FormLabel>
                <FormControl>
                  <Input
                    {...field}
                    value={field.value || ''}
                    onChange={e => field.onChange(e.target.value)}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <FormField
          control={form.control}
          name='builder'
          render={({ field }) => (
            <FormItem>
              <FormLabel>
                Builder
                <SidebarToggleButton
                  directory='services'
                  fileName='app-service'
                  sectionId='#builder--editable'
                />
              </FormLabel>
              <FormControl>
                <RadioGroup
                  onValueChange={field.onChange}
                  defaultValue={field.value}
                  className='flex w-full flex-col gap-4 md:flex-row'>
                  {buildOptions.map(({ value, label, icon, description }) => (
                    <FormItem
                      className='flex w-full items-center space-x-3 space-y-0'
                      key={value}>
                      <FormControl>
                        <div className='has-data-[state=checked]:border-ring shadow-xs relative flex h-full w-full items-start gap-2 rounded-md border border-input p-4 outline-none'>
                          <RadioGroupItem
                            value={value}
                            id={value}
                            aria-describedby={`${label}-builder`}
                            className='order-1 after:absolute after:inset-0'
                          />
                          <div className='flex grow items-start gap-3'>
                            {icon}

                            <div className='grid grow gap-2'>
                              <Label htmlFor={value}>{label}</Label>

                              <p className='text-xs text-muted-foreground'>
                                {description}
                              </p>
                            </div>
                          </div>
                        </div>
                      </FormControl>
                    </FormItem>
                  ))}
                </RadioGroup>
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className='flex w-full justify-end'>
          <Button
            type='submit'
            disabled={isPending}
            isLoading={isPending}
            variant='outline'>
            Save
          </Button>
        </div>
      </form>
    </Form>
  )
}

export default GiteaForm
