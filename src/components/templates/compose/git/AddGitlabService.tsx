'use client'

import { getPositionForNewNode } from '../ChooseService'
import { GithubServiceSchema, GithubServiceType } from '../types'
import { zodResolver } from '@hookform/resolvers/zod'
import { Node, useReactFlow } from '@xyflow/react'
import { Workflow } from 'lucide-react'
import { motion } from 'motion/react'
import { useForm, useWatch } from 'react-hook-form'
import { toast } from 'sonner'
import {
  adjectives,
  animals,
  colors,
  uniqueNamesGenerator,
} from 'unique-names-generator'

import { ServiceNode } from '@/components/reactflow/types'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import SecretContent from '@/components/ui/blur-reveal'
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

const AddGitlabService = ({
  setNodes,
  nodes,
  type = 'create',
  setOpen,
  handleOnClick,
  service,
}: {
  setNodes: Function
  nodes: Node[]
  service?: ServiceNode
  setOpen?: Function
  type: 'create' | 'update'
  handleOnClick?: ({ serviceId }: { serviceId: string }) => void
}) => {
  const { fitView } = useReactFlow()

  const form = useForm<GithubServiceType>({
    resolver: zodResolver(GithubServiceSchema),
    defaultValues: {
      providerType: 'gitlab',
      builder: service?.builder ?? 'buildPacks',
      gitlabSettings: {
        repository: service?.gitlabSettings?.repository || '',
        branch: service?.gitlabSettings?.branch || '',
        owner: service?.gitlabSettings?.owner || 'oauth2',
        gitToken: service?.gitlabSettings?.gitToken || '',
        port: service?.gitlabSettings?.port || 3000,
        buildPath: service?.gitlabSettings?.buildPath || '/',
      },
    },
  })

  const { gitlabSettings } = useWatch({ control: form.control })

  const addGitlabNode = (data: GithubServiceType) => {
    if (type === 'update') {
      setNodes((prevNodes: Node[]) =>
        prevNodes.map(node => {
          if (node.id === service?.id) {
            return {
              ...node,
              data: {
                ...node.data,
                ...data,
              },
            }
          }
          return node
        }),
      )
      toast.success('Gitlab details updated successfully')
    } else if (type === 'create') {
      const name = uniqueNamesGenerator({
        dictionaries: [adjectives, colors, animals],
        separator: '-',
        style: 'lowerCase',
        length: 2,
      })
      const newNode: ServiceNode = {
        type: 'app',
        id: name,
        name,
        variables: [],
        ...data,
      }

      setNodes((prev: Node[]) => [
        ...prev,
        {
          id: name,
          data: {
            ...newNode,
            ...(handleOnClick && {
              onClick: () => handleOnClick({ serviceId: name }),
            }),
          },
          position: getPositionForNewNode(nodes?.length),
          type: 'custom',
        },
      ])
      setOpen?.(false)
      setTimeout(() => {
        fitView({ padding: 0.2, duration: 500 })
      }, 100)
    }
  }

  return (
    <motion.div
      initial={{ x: '5%', opacity: 0.25 }}
      animate={{ x: 0, opacity: [0.25, 1] }}
      exit={{ x: '100%', opacity: 1 }}
      className='w-full'>
      <Form {...form}>
        <form
          onSubmit={form.handleSubmit(addGitlabNode)}
          className='w-full space-y-6'>
          <Alert variant='info'>
            <Workflow className='h-4 w-4' />

            <AlertTitle>Automatic deployments are coming soon!</AlertTitle>
            <AlertDescription>
              For now, you can set up your GitLab service with the following
              details. Make sure to trigger a deployment after saving the
              changes.
            </AlertDescription>
          </Alert>

          <div className='grid gap-4 md:grid-cols-2'>
            {/* Repository URL */}
            <FormField
              control={form.control}
              name='gitlabSettings.repository'
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Repository URL</FormLabel>
                  <FormControl>
                    <Input
                      type='text'
                      placeholder='ex: https://github.com/akhil-naidu/dflow'
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
              name='gitlabSettings.branch'
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
              name='gitlabSettings.owner'
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Username</FormLabel>
                  <FormControl>
                    <Input
                      type='text'
                      placeholder='ex: your-username'
                      {...field}
                      disabled
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* Branch */}
            <FormField
              control={form.control}
              name='gitlabSettings.gitToken'
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
              name='gitlabSettings.port'
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Port</FormLabel>
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
              name='gitlabSettings.buildPath'
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Build path </FormLabel>
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
                <FormLabel>Builder</FormLabel>
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
              disabled={
                !gitlabSettings?.repository ||
                !gitlabSettings?.branch ||
                !gitlabSettings?.owner ||
                !gitlabSettings?.buildPath
              }
              variant='outline'>
              Save
            </Button>
          </div>
        </form>
      </Form>
    </motion.div>
  )
}

export default AddGitlabService
