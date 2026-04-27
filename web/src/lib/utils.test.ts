import { describe, it, expect } from 'vitest'
import { cn, escapeHtml } from './utils'

describe('utils.ts — Classname utilities', () => {
  describe('cn function', () => {
    it('merges single class string', () => {
      expect(cn('p-4')).toBe('p-4')
    })

    it('merges multiple class strings', () => {
      const result = cn('p-4', 'text-white')
      expect(result).toContain('p-4')
      expect(result).toContain('text-white')
    })

    it('handles array of classes', () => {
      const result = cn(['p-4', 'text-white', 'bg-blue-500'])
      expect(result).toContain('p-4')
      expect(result).toContain('text-white')
      expect(result).toContain('bg-blue-500')
    })

    it('filters out falsy values', () => {
      const result = cn('p-4', false, 'text-white', null, 'bg-blue-500', undefined)
      expect(result).toContain('p-4')
      expect(result).toContain('text-white')
      expect(result).toContain('bg-blue-500')
      expect(result).not.toContain('false')
      expect(result).not.toContain('null')
    })

    it('handles conditional classes', () => {
      const isActive = true
      const result = cn('p-4', isActive && 'bg-blue-500', !isActive && 'bg-gray-500')
      expect(result).toContain('p-4')
      expect(result).toContain('bg-blue-500')
      expect(result).not.toContain('bg-gray-500')
    })

    it('merges tailwind classes correctly', () => {
      const result = cn('px-2 py-4', 'px-4')
      expect(result).toContain('py-4')
      expect(result).toContain('px-4')
      expect(result).not.toContain('px-2')
    })

    it('handles object syntax from clsx', () => {
      const result = cn({ 'p-4': true, 'text-white': false })
      expect(result).toContain('p-4')
      expect(result).not.toContain('text-white')
    })

    it('handles mixed object and string syntax', () => {
      const result = cn('p-4', { 'text-white': true, 'bg-blue': false }, 'border')
      expect(result).toContain('p-4')
      expect(result).toContain('text-white')
      expect(result).toContain('border')
      expect(result).not.toContain('bg-blue')
    })

    it('handles nested arrays', () => {
      const result = cn(['p-4', ['text-white', 'bg-blue-500']])
      expect(result).toContain('p-4')
      expect(result).toContain('text-white')
      expect(result).toContain('bg-blue-500')
    })

    it('returns empty string for no classes', () => {
      expect(cn()).toBe('')
      expect(cn(false, null, undefined)).toBe('')
    })

    it('handles complex tailwind utilities', () => {
      const result = cn(
        'absolute top-0 left-0 right-0 bottom-0',
        'flex items-center justify-center',
        'w-full h-full'
      )
      expect(result).toContain('absolute')
      expect(result).toContain('top-0')
      expect(result).toContain('flex')
      expect(result).toContain('items-center')
      expect(result).toContain('justify-center')
      expect(result).toContain('w-full')
      expect(result).toContain('h-full')
    })

    it('handles responsive prefixes correctly', () => {
      const result = cn(
        'md:p-4',
        'lg:text-xl',
        'sm:rounded-sm'
      )
      expect(result).toContain('md:p-4')
      expect(result).toContain('lg:text-xl')
      expect(result).toContain('sm:rounded-sm')
    })

    it('handles dark mode classes', () => {
      const result = cn('bg-white', 'dark:bg-gray-900', 'text-black dark:text-white')
      expect(result).toContain('bg-white')
      expect(result).toContain('dark:bg-gray-900')
      expect(result).toContain('text-black')
      expect(result).toContain('dark:text-white')
    })

    it('handles arbitrary values', () => {
      const result = cn('w-[100px]', 'h-[200px]', 'text-[#333333]')
      expect(result).toContain('w-[100px]')
      expect(result).toContain('h-[200px]')
      expect(result).toContain('text-[#333333]')
    })

    it('handles transition and animation classes', () => {
      const result = cn('transition-all duration-300 ease-in-out', 'animate-pulse')
      expect(result).toContain('transition-all')
      expect(result).toContain('duration-300')
      expect(result).toContain('ease-in-out')
      expect(result).toContain('animate-pulse')
    })

    it('handles shadow and border classes', () => {
      const result = cn('shadow-lg border border-gray-300 rounded-md')
      expect(result).toContain('shadow-lg')
      expect(result).toContain('border')
      expect(result).toContain('border-gray-300')
      expect(result).toContain('rounded-md')
    })

    it('handles z-index classes', () => {
      const result = cn('z-10', 'z-20', 'relative z-50')
      expect(result).toContain('z-50')
      expect(result).toContain('relative')
      expect(result).not.toContain('z-10')
      expect(result).not.toContain('z-20')
    })

    it('handles conflict resolution between padding and margins', () => {
      const result = cn('p-4 m-2', 'p-8')
      expect(result).toContain('p-8')
      expect(result).toContain('m-2')
      expect(result).not.toContain('p-4')
    })

    it('preserves custom CSS class names', () => {
      const result = cn('my-custom-class', 'another-custom-class')
      expect(result).toContain('my-custom-class')
      expect(result).toContain('another-custom-class')
    })

    it('handles multiple calls with conditional logic', () => {
      const isDisabled = false
      const isError = true
      const result = cn(
        'p-4',
        isDisabled && 'opacity-50 cursor-not-allowed',
        isError && 'border-red-500 bg-red-50',
        !isError && 'border-gray-300'
      )
      expect(result).toContain('p-4')
      expect(result).toContain('border-red-500')
      expect(result).toContain('bg-red-50')
      expect(result).not.toContain('opacity-50')
      expect(result).not.toContain('border-gray-300')
    })

    it('handles empty array', () => {
      expect(cn([])).toBe('')
    })

    it('handles large number of classes', () => {
      const classes = Array(100).fill('p-4 m-2 text-white bg-blue-500')
      const result = cn(...classes)
      expect(result).toContain('p-4')
      expect(result).toContain('m-2')
      expect(result).toContain('text-white')
      expect(result).toContain('bg-blue-500')
    })

    it('returns consistent output for same input', () => {
      const input = ['p-4', 'text-white', 'bg-blue-500']
      const result1 = cn(...input)
      const result2 = cn(...input)
      expect(result1).toBe(result2)
    })
  })

  // A-030: escapeHtml protects CouncilAIPanel's dangerouslySetInnerHTML path
  // from backend-provided markdown that contains raw tags / quotes / script.
  describe('escapeHtml', () => {
    it('escapes angle brackets so <script> cannot execute', () => {
      const result = escapeHtml('<script>alert(1)</script>')
      expect(result).toBe('&lt;script&gt;alert(1)&lt;/script&gt;')
      expect(result).not.toContain('<script>')
    })

    it('escapes img onerror payloads', () => {
      const result = escapeHtml('<img src=x onerror="alert(1)">')
      expect(result).toContain('&lt;img')
      expect(result).toContain('&quot;')
      expect(result).not.toContain('<img')
    })

    it('escapes ampersands before other entities to avoid double-encoding traps', () => {
      const result = escapeHtml('Tom & Jerry <3')
      expect(result).toBe('Tom &amp; Jerry &lt;3')
    })

    it('escapes all five reserved characters', () => {
      expect(escapeHtml('&<>"\'')).toBe('&amp;&lt;&gt;&quot;&#39;')
    })

    it('leaves plain text untouched', () => {
      expect(escapeHtml('plain text without anything special')).toBe('plain text without anything special')
    })

    it('returns empty string for empty input', () => {
      expect(escapeHtml('')).toBe('')
    })
  })
})
