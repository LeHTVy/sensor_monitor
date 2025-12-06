/**
 * Date/Time formatting utilities for Vietnam timezone (UTC+7)
 */

const TIMEZONE = 'Asia/Ho_Chi_Minh'
const LOCALE = 'vi-VN'

/**
 * Format a date string to Vietnam timezone with full date and time
 */
export function formatDateTime(dateStr: string | Date): string {
    if (!dateStr) return 'Unknown'
    const date = typeof dateStr === 'string'
        ? new Date(dateStr.endsWith('Z') || dateStr.includes('+') ? dateStr : dateStr + 'Z')
        : dateStr

    return date.toLocaleString(LOCALE, {
        timeZone: TIMEZONE,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    })
}

/**
 * Format a date to time only (HH:MM) in Vietnam timezone
 */
export function formatTime(dateStr: string | Date): string {
    if (!dateStr) return ''
    const date = typeof dateStr === 'string' ? new Date(dateStr) : dateStr

    return date.toLocaleTimeString(LOCALE, {
        timeZone: TIMEZONE,
        hour: '2-digit',
        minute: '2-digit'
    })
}

/**
 * Format a date to time with seconds (HH:MM:SS) in Vietnam timezone
 */
export function formatTimeWithSeconds(dateStr: string | Date): string {
    if (!dateStr) return ''
    const date = typeof dateStr === 'string' ? new Date(dateStr) : dateStr

    return date.toLocaleTimeString(LOCALE, {
        timeZone: TIMEZONE,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    })
}

/**
 * Format a date to date only (DD/MM/YYYY) in Vietnam timezone
 */
export function formatDate(dateStr: string | Date): string {
    if (!dateStr) return ''
    const date = typeof dateStr === 'string' ? new Date(dateStr) : dateStr

    return date.toLocaleDateString(LOCALE, {
        timeZone: TIMEZONE,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
    })
}

/**
 * Format a date for chart labels (short time format)
 */
export function formatChartTime(dateStr: string | Date): string {
    return formatTime(dateStr)
}

/**
 * Get the timezone constant for use in chart options
 */
export const VIETNAM_TIMEZONE = TIMEZONE
export const VIETNAM_LOCALE = LOCALE
