<template>
  <v-card elevation="2" rounded="lg" class="sankey-chart-card">
    <v-card-title class="d-flex align-center">
      <v-icon icon="mdi-transit-connection-variant" color="primary" class="mr-2" />
      <span class="text-h6 font-weight-bold">Attack Flow Analysis</span>
      <v-spacer />
      <v-btn-toggle v-model="viewMode" mandatory density="compact" variant="outlined">
        <v-btn value="country" size="small">By Country</v-btn>
        <v-btn value="ip" size="small">By IP</v-btn>
      </v-btn-toggle>
    </v-card-title>

    <v-card-text class="position-relative" style="min-height: 400px;">
      <!-- No Data State -->
      <div v-if="!hasData" class="d-flex flex-column align-center justify-center position-absolute w-100 h-100" style="top: 0; left: 0; z-index: 10; background: rgba(var(--v-theme-surface), 0.8);">
        <v-icon icon="mdi-transit-connection-variant" size="64" color="grey-lighten-1" />
        <p class="text-body-2 text-medium-emphasis mt-4">No attack flow data available</p>
      </div>

      <!-- Legend -->
      <div v-show="hasData" class="chart-legend mb-2">
        <div class="legend-item">
          <span class="legend-color" style="background: #EF4444;"></span>
          <span class="text-caption">High Severity</span>
        </div>
        <div class="legend-item">
          <span class="legend-color" style="background: #F59E0B;"></span>
          <span class="text-caption">Medium Severity</span>
        </div>
        <div class="legend-item">
          <span class="legend-color" style="background: #3B82F6;"></span>
          <span class="text-caption">Low Severity</span>
        </div>
        <div class="legend-item">
          <span class="legend-color" style="background: #10B981;"></span>
          <span class="text-caption">Info</span>
        </div>
      </div>

      <!-- Sankey Chart SVG -->
      <div ref="chartContainer" class="sankey-container"></div>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch, nextTick } from 'vue'
import { useDashboardStore, type Log } from '@/stores/dashboard'
import * as d3 from 'd3'
import { sankey, sankeyLinkHorizontal, type SankeyNode, type SankeyLink } from 'd3-sankey'

const dashboardStore = useDashboardStore()

// Types for Sankey data
interface SankeyNodeData {
  name: string
  category: 'source' | 'tool' | 'target'
}

interface SankeyLinkData {
  source: number
  target: number
  value: number
  severity: string
}

interface ProcessedNode extends SankeyNode<SankeyNodeData, SankeyLinkData> {
  name: string
  category: 'source' | 'tool' | 'target'
}

interface ProcessedLink extends SankeyLink<SankeyNodeData, SankeyLinkData> {
  severity: string
}

const viewMode = ref<'country' | 'ip'>('country')
const chartContainer = ref<HTMLElement>()
let resizeObserver: ResizeObserver | null = null

const hasData = computed(() => dashboardStore.logs.length > 0)

// Color scheme based on severity
const severityColors: Record<string, string> = {
  high: '#EF4444',
  medium: '#F59E0B',
  low: '#3B82F6',
  info: '#10B981'
}

const getSeverity = (log: Log): string => {
  const threatScore = log.threat_score || 0
  if (threatScore >= 70) return 'high'
  if (threatScore >= 40) return 'medium'
  if (threatScore >= 20) return 'low'
  return 'info'
}

const processData = () => {
  const logs = dashboardStore.logs
  if (logs.length === 0) return { nodes: [], links: [] }

  // Build nodes and links using unique node IDs (category:name)
  const nodeMap = new Map<string, { name: string; category: 'source' | 'tool' | 'target'; id: string }>()
  const linkMap = new Map<string, { source: string; target: string; value: number; severity: string }>()

  const addNode = (name: string, category: 'source' | 'tool' | 'target'): string => {
    const id = `${category}:${name}`
    if (!nodeMap.has(id)) {
      nodeMap.set(id, { name, category, id })
    }
    return id
  }

  logs.forEach((log: Log) => {
    // Source node (country or IP based on viewMode)
    let sourceName: string
    if (viewMode.value === 'country') {
      sourceName = log.geoip?.country || 'Unknown'
    } else {
      // For IP mode, show first 3 octets + *
      const ip = log.src_ip || log.ip || 'Unknown'
      const parts = ip.split('.')
      sourceName = parts.length >= 3 ? `${parts[0]}.${parts[1]}.${parts[2]}.*` : ip
    }
    
    // Tool node
    const toolName = log.attack_tool || 'Unknown Tool'
    
    // Target node (port or path)
    let targetName: string
    if (log.dst_port) {
      targetName = `Port ${log.dst_port}`
    } else if (log.path) {
      // Extract first path segment
      const pathMatch = log.path.match(/^\/([^/?]+)/)
      targetName = pathMatch ? `/${pathMatch[1]}` : log.path.substring(0, 20)
    } else {
      targetName = 'Unknown Target'
    }

    const sourceId = addNode(sourceName, 'source')
    const toolId = addNode(toolName, 'tool')
    const targetId = addNode(targetName, 'target')

    const severity = getSeverity(log)

    // Link: Source → Tool
    const link1Key = `${sourceId}|${toolId}`
    if (linkMap.has(link1Key)) {
      linkMap.get(link1Key)!.value++
    } else {
      linkMap.set(link1Key, { source: sourceId, target: toolId, value: 1, severity })
    }

    // Link: Tool → Target
    const link2Key = `${toolId}|${targetId}`
    if (linkMap.has(link2Key)) {
      linkMap.get(link2Key)!.value++
    } else {
      linkMap.set(link2Key, { source: toolId, target: targetId, value: 1, severity })
    }
  })

  // Convert maps to arrays
  const allNodes = Array.from(nodeMap.values())
  const allLinks = Array.from(linkMap.values())

  // Show all flows (no limit)
  const topLinks = allLinks
    .sort((a, b) => b.value - a.value)

  // Get referenced node IDs only
  const usedNodeIds = new Set<string>()
  topLinks.forEach(link => {
    usedNodeIds.add(link.source)
    usedNodeIds.add(link.target)
  })

  // Filter nodes to only include those referenced by links
  const filteredNodes = allNodes.filter(node => usedNodeIds.has(node.id))

  return { 
    nodes: filteredNodes.map(n => ({ name: n.id, displayName: n.name, category: n.category })),
    links: topLinks.map(l => ({ source: l.source, target: l.target, value: l.value, severity: l.severity }))
  }
}

const renderChart = () => {
  if (!chartContainer.value) return

  // Clear previous chart
  d3.select(chartContainer.value).selectAll('*').remove()

  const data = processData()
  if (data.nodes.length === 0 || data.links.length === 0) return

  const containerRect = chartContainer.value.getBoundingClientRect()
  const width = containerRect.width || 800
  const height = 400
  const margin = { top: 20, right: 120, bottom: 20, left: 120 }

  const svg = d3.select(chartContainer.value)
    .append('svg')
    .attr('width', width)
    .attr('height', height)
    .attr('viewBox', [0, 0, width, height])
    .attr('class', 'sankey-svg')

  // Create Sankey generator using node name as ID
  const sankeyGenerator = sankey<{ name: string; displayName: string; category: string }, { source: string; target: string; value: number; severity: string }>()
    .nodeId(d => d.name)
    .nodeWidth(20)
    .nodePadding(12)
    .extent([[margin.left, margin.top], [width - margin.right, height - margin.bottom]])
    .nodeSort(null)

  // Generate layout
  const { nodes, links } = sankeyGenerator({
    nodes: data.nodes.map(d => ({ ...d })),
    links: data.links.map(d => ({ ...d }))
  })

  // Category colors
  const categoryColors: Record<string, string> = {
    source: '#6366F1',
    tool: '#EC4899',
    target: '#14B8A6'
  }

  // Draw links
  const link = svg.append('g')
    .attr('class', 'links')
    .attr('fill', 'none')
    .selectAll('path')
    .data(links)
    .join('path')
    .attr('d', sankeyLinkHorizontal())
    .attr('stroke', (d: any) => severityColors[d.severity] || '#999')
    .attr('stroke-opacity', 0.4)
    .attr('stroke-width', (d: any) => Math.max(1, d.width || 1))
    .on('mouseover', function(this: SVGPathElement) {
      d3.select(this).attr('stroke-opacity', 0.8)
    })
    .on('mouseout', function(this: SVGPathElement) {
      d3.select(this).attr('stroke-opacity', 0.4)
    })

  // Add link titles (tooltips)
  link.append('title')
    .text((d: any) => {
      const sourceName = typeof d.source === 'object' ? d.source.displayName || d.source.name : d.source
      const targetName = typeof d.target === 'object' ? d.target.displayName || d.target.name : d.target
      return `${sourceName} → ${targetName}\n${d.value} attacks`
    })

  // Draw nodes
  const node = svg.append('g')
    .attr('class', 'nodes')
    .selectAll('g')
    .data(nodes)
    .join('g')
    .attr('transform', (d: any) => `translate(${d.x0},${d.y0})`)

  // Node rectangles
  node.append('rect')
    .attr('height', (d: any) => (d.y1 || 0) - (d.y0 || 0))
    .attr('width', (d: any) => (d.x1 || 0) - (d.x0 || 0))
    .attr('fill', (d: any) => categoryColors[d.category] || '#999')
    .attr('stroke', '#fff')
    .attr('stroke-width', 1)
    .attr('rx', 3)
    .attr('ry', 3)
    .style('cursor', 'pointer')
    .on('mouseover', function(this: SVGRectElement) {
      d3.select(this).attr('opacity', 0.8)
    })
    .on('mouseout', function(this: SVGRectElement) {
      d3.select(this).attr('opacity', 1)
    })

  // Node labels
  node.append('text')
    .attr('x', (d: any) => d.category === 'source' ? -6 : ((d.x1 || 0) - (d.x0 || 0)) + 6)
    .attr('y', (d: any) => ((d.y1 || 0) - (d.y0 || 0)) / 2)
    .attr('dy', '0.35em')
    .attr('text-anchor', (d: any) => d.category === 'source' ? 'end' : 'start')
    .attr('font-size', '11px')
    .attr('fill', 'currentColor')
    .text((d: any) => {
      const name = d.displayName || d.name
      return name.length > 15 ? name.substring(0, 15) + '...' : name
    })
    .append('title')
    .text((d: any) => `${d.displayName || d.name}\n${d.value || 0} attacks`)

  // Add category labels at top
  const categories = [
    { name: 'Source', x: margin.left - 40 },
    { name: 'Attack Tool', x: width / 2 },
    { name: 'Target', x: width - margin.right + 40 }
  ]

  svg.append('g')
    .attr('class', 'category-labels')
    .selectAll('text')
    .data(categories)
    .join('text')
    .attr('x', d => d.x)
    .attr('y', 10)
    .attr('text-anchor', 'middle')
    .attr('font-size', '12px')
    .attr('font-weight', 'bold')
    .attr('fill', 'currentColor')
    .attr('opacity', 0.7)
    .text(d => d.name)
}

// Debounce helper
const debounce = <T extends (...args: unknown[]) => void>(fn: T, delay: number) => {
  let timeoutId: ReturnType<typeof setTimeout>
  return (...args: Parameters<T>) => {
    clearTimeout(timeoutId)
    timeoutId = setTimeout(() => fn(...args), delay)
  }
}

const debouncedRender = debounce(() => {
  renderChart()
}, 250)

onMounted(() => {
  nextTick(() => {
    renderChart()
  })

  // Observe container resize
  if (chartContainer.value) {
    resizeObserver = new ResizeObserver(debouncedRender)
    resizeObserver.observe(chartContainer.value)
  }
})

onUnmounted(() => {
  if (resizeObserver) {
    resizeObserver.disconnect()
  }
})

// Watch for data or view mode changes
watch([() => dashboardStore.logs, viewMode], () => {
  nextTick(() => {
    renderChart()
  })
})
</script>

<style scoped>
.sankey-chart-card {
  height: 100%;
}

.sankey-container {
  width: 100%;
  height: 400px;
  overflow: hidden;
}

.sankey-svg {
  display: block;
}

.chart-legend {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
  justify-content: center;
  padding: 4px 0;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 6px;
}

.legend-color {
  width: 12px;
  height: 12px;
  border-radius: 2px;
}

:deep(.sankey-svg text) {
  font-family: inherit;
}

:deep(.sankey-svg .links path) {
  transition: stroke-opacity 0.2s ease;
}

:deep(.sankey-svg .nodes rect) {
  transition: opacity 0.2s ease;
  filter: drop-shadow(0 1px 2px rgba(0, 0, 0, 0.1));
}
</style>
