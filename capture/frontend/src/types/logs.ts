import type { Log } from '@/stores/dashboard'

/**
 * Extended Log interface for Elasticsearch fields
 * Extends the base Log interface with additional fields from Elasticsearch
 */
export interface ExtendedLog extends Log {
  '@timestamp'?: string
  '@ingested_at'?: string
  method?: string
  path?: string
  url?: string
  user_agent?: string
  headers?: Record<string, string>
  protocol?: string
  args?: Record<string, unknown>
  form_data?: Record<string, unknown>
  kafka_topic?: string
  attack_tool_info?: Record<string, unknown>
  attack_technique?: string[]
  os_info?: {
    os?: string
    version?: string
    architecture?: string
  }
  geoip?: {
    country: string
    city: string
    isp?: string
    org?: string
    lat?: number
    lon?: number
    timezone?: string
    region?: string
    postal?: string
  }
}

/**
 * Helper function to safely get timestamp from log
 * Handles multiple timestamp field formats (timestamp, @timestamp, @ingested_at)
 */
export function getLogTimestamp(log: Log | ExtendedLog): Date {
  const extendedLog = log as ExtendedLog
  const timestamp = extendedLog.timestamp || extendedLog['@timestamp'] || extendedLog['@ingested_at']
  if (typeof timestamp === 'string') {
    return new Date(timestamp)
  }
  // Fallback to current time if no valid timestamp
  return new Date()
}

