<template>
  <v-card class="world-map-card" elevation="2">
    <v-card-title class="d-flex align-center">
      <v-icon icon="mdi-earth" color="primary" class="mr-2" />
      <span>ACTIVE CAPTURES</span>
      <v-chip size="small" variant="outlined" class="ml-3">
        {{ attackerCount }} unique attackers
      </v-chip>
      <v-spacer />
      <v-btn size="small" icon variant="text" @click="refresh">
        <v-icon>mdi-refresh</v-icon>
      </v-btn>
    </v-card-title>

    <v-card-text>
      <div v-if="loading" class="map-loading">
        <v-progress-circular indeterminate color="primary" />
        <p>Loading attacker data...</p>
      </div>

      <div v-else class="attack-map-container">
        <svg ref="mapSvg" class="attack-map-svg"></svg>
      </div>
      
      <!-- Attack Legend -->
      <div v-if="!loading && countryData.length > 0" class="mt-4">
        <div class="text-caption mb-2">Top Attack Origins (Unique IPs):</div>
        <v-chip
          v-for="data in countryData.slice(0, 5)"
          :key="data.country"
          size="small"
          variant="outlined"
          color="primary"
          class="mr-2 mb-2"
        >
          {{ data.country }}: {{ data.uniqueIps }} attackers
        </v-chip>
      </div>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import * as d3 from 'd3'
import * as topojson from 'topojson-client'
import { useAuthStore } from '@/stores/auth'

const authStore = useAuthStore()
const API_BASE = '/api'

interface CountryAttackers {
  country: string
  lat: number
  lon: number
  uniqueIps: number  // Number of unique attacker IPs
  ips: string[]      // List of IPs (for tooltip)
}

const mapSvg = ref<SVGSVGElement>()
const loading = ref(true)
const attackerCount = ref(0)
const countryData = ref<CountryAttackers[]>([])
let refreshInterval: number | null = null
let currentProjection: d3.GeoProjection | null = null

// Country to coordinates mapping
const countryCoords: Record<string, { lat: number; lon: number }> = {
  'Vietnam': { lat: 16.0, lon: 106.0 },
  'United States': { lat: 37.0, lon: -95.0 },
  'China': { lat: 35.0, lon: 105.0 },
  'Russia': { lat: 60.0, lon: 100.0 },
  'India': { lat: 20.0, lon: 77.0 },
  'Germany': { lat: 51.0, lon: 9.0 },
  'United Kingdom': { lat: 55.0, lon: -3.0 },
  'France': { lat: 46.0, lon: 2.0 },
  'Japan': { lat: 36.0, lon: 138.0 },
  'Brazil': { lat: -14.0, lon: -51.0 },
  'Canada': { lat: 60.0, lon: -95.0 },
  'Australia': { lat: -25.0, lon: 133.0 },
  'South Korea': { lat: 37.0, lon: 127.5 },
  'Netherlands': { lat: 52.3, lon: 5.7 },
  'Singapore': { lat: 1.3, lon: 103.8 },
  'Andorra': { lat: 42.5, lon: 1.5 },
  'Spain': { lat: 40.0, lon: -4.0 },
  'Italy': { lat: 42.8, lon: 12.8 },
  'Poland': { lat: 52.0, lon: 20.0 },
  'Ukraine': { lat: 49.0, lon: 32.0 },
  'Turkey': { lat: 39.0, lon: 35.0 },
  'Thailand': { lat: 15.0, lon: 101.0 },
  'Indonesia': { lat: -2.5, lon: 118.0 },
  'Mexico': { lat: 23.0, lon: -102.0 },
  'Argentina': { lat: -34.0, lon: -64.0 },
}

async function fetchAttackData() {
  try {
    // Fetch unique attackers from Elasticsearch via /api/attackers
    const response = await fetch(
      `${API_BASE}/attackers?limit=500`,
      { headers: { 'X-API-Key': authStore.apiKey || '' } }
    )

    if (response.ok) {
      const data = await response.json()
      const attackers = data.attackers || []

      // Aggregate UNIQUE IPs by country
      const countryMap = new Map<string, { ips: Set<string> }>()

      attackers.forEach((attacker: any) => {
        const country = attacker.country || 'Unknown'
        if (country !== 'Unknown') {
          const existing = countryMap.get(country)
          if (existing) {
            existing.ips.add(attacker.ip)
          } else {
            countryMap.set(country, { ips: new Set([attacker.ip]) })
          }
        }
      })

      // Convert to array with coordinates
      const result: CountryAttackers[] = []
      countryMap.forEach((data, country) => {
        const coords = countryCoords[country] || { lat: 0, lon: 0 }
        result.push({
          country,
          lat: coords.lat,
          lon: coords.lon,
          uniqueIps: data.ips.size,
          ips: Array.from(data.ips).slice(0, 5)  // Keep first 5 for tooltip
        })
      })

      // Sort by unique IP count descending
      result.sort((a, b) => b.uniqueIps - a.uniqueIps)

      countryData.value = result
      attackerCount.value = attackers.length  // Total unique attackers
    }
  } catch (error) {
    console.error('Error fetching attacker data:', error)
  } finally {
    loading.value = false
  }
}

async function renderMap() {
  if (!mapSvg.value) return

  const width = 1200
  const height = 600

  // Clear existing
  d3.select(mapSvg.value).selectAll('*').remove()

  const svg = d3.select(mapSvg.value)
    .attr('width', '100%')
    .attr('height', height)
    .attr('viewBox', `0 0 ${width} ${height}`)

  // Get current theme colors
  const surfaceColor = getComputedStyle(document.documentElement).getPropertyValue('--v-theme-surface').trim()
  const primaryColor = getComputedStyle(document.documentElement).getPropertyValue('--v-theme-primary').trim()
  
  const getSvgColor = (rgbString: string) => {
    if (!rgbString.includes(',')) return `rgb(${rgbString})`
    return `rgb(${rgbString})`
  }

  // Add background
  svg.append('rect')
    .attr('width', width)
    .attr('height', height)
    .attr('fill', getSvgColor(surfaceColor))
    .attr('opacity', 0.1)

  // Load world map GeoJSON from free CDN (no API key needed)
  try {
    const response = await fetch('https://unpkg.com/world-atlas@2/countries-110m.json')
    const world = await response.json()
    
    // Convert TopoJSON to GeoJSON
    const countries = (topojson as any).feature(world, world.objects.countries)
    
    // Create projection
    const projection = d3.geoMercator()
      .fitSize([width, height], countries)
    
    // Store projection for marker positioning
    currentProjection = projection
    
    const path = d3.geoPath().projection(projection)
    
    // Draw countries
    svg.append('g')
      .selectAll('path')
      .data(countries.features)
      .enter()
      .append('path')
      .attr('d', path as any)
      .attr('fill', getSvgColor(surfaceColor))
      .attr('stroke', getSvgColor(primaryColor))
      .attr('stroke-width', 0.5)
      .attr('opacity', 0.3)
  } catch (error) {
    console.warn('Could not load world map, showing grid instead:', error)
    
    // Fallback: Draw grid if map fails to load
    const gridGroup = svg.append('g').attr('class', 'grid')
    
    for (let lat = -90; lat <= 90; lat += 30) {
      const y = ((90 - lat) / 180) * height
      gridGroup.append('line')
        .attr('x1', 0).attr('y1', y).attr('x2', width).attr('y2', y)
        .attr('stroke', getSvgColor(primaryColor))
        .attr('stroke-width', 0.5).attr('opacity', 0.2)
    }
    
    for (let lon = -180; lon <= 180; lon += 30) {
      const x = ((lon + 180) / 360) * width
      gridGroup.append('line')
        .attr('x1', x).attr('y1', 0).attr('x2', x).attr('y2', height)
        .attr('stroke', getSvgColor(primaryColor))
        .attr('stroke-width', 0.5).attr('opacity', 0.2)
    }
    
    // Use simple projection as fallback
    currentProjection = d3.geoEquirectangular().fitSize([width, height], {
      type: 'Sphere'
    } as any)
  }

  // Draw attack markers based on unique IPs per country
  const markersGroup = svg.append('g').attr('class', 'markers')

  countryData.value.forEach((data) => {
    // Use the same projection as the map for accurate positioning
    const coords = currentProjection ? currentProjection([data.lon, data.lat]) : null
    if (!coords) return
    
    const [x, y] = coords
    
    // Calculate circle size based on unique IP count (logarithmic scale for better visualization)
    const baseRadius = 8
    const sizeMultiplier = Math.log2(data.uniqueIps + 1) * 4  // Logarithmic scaling
    
    // Outer pulsing circle
    markersGroup.append('circle')
      .attr('cx', x).attr('cy', y).attr('r', baseRadius)
      .attr('fill', getSvgColor(primaryColor))
      .attr('opacity', 0.3)
      .append('animate')
      .attr('attributeName', 'r')
      .attr('from', baseRadius).attr('to', baseRadius + 15)
      .attr('dur', '2s')
      .attr('repeatCount', 'indefinite')

    // Size ring - represents unique attacker count
    markersGroup.append('circle')
      .attr('cx', x).attr('cy', y)
      .attr('r', baseRadius + sizeMultiplier)
      .attr('fill', 'none')
      .attr('stroke', getSvgColor(primaryColor))
      .attr('stroke-width', 2).attr('opacity', 0.6)

    // Inner solid circle
    markersGroup.append('circle')
      .attr('cx', x).attr('cy', y).attr('r', 6)
      .attr('fill', getSvgColor(primaryColor))
      .attr('opacity', 0.9).style('cursor', 'pointer')
      .on('mouseover', function() { d3.select(this).attr('r', 9) })
      .on('mouseout', function() { d3.select(this).attr('r', 6) })
      .append('title')
      .text(`${data.country}: ${data.uniqueIps} unique attackers\n${data.ips.slice(0, 3).join(', ')}${data.ips.length > 3 ? '...' : ''}`)
  })
}

async function refresh() {
  loading.value = true
  await fetchAttackData()
  renderMap()
}

onMounted(async () => {
  await fetchAttackData()
  renderMap()
  
  // Auto-refresh every 30 seconds
  refreshInterval = window.setInterval(refresh, 30000)
})

onUnmounted(() => {
  if (refreshInterval) clearInterval(refreshInterval)
})
</script>

<style scoped>
.world-map-card {
  background: rgb(var(--v-theme-surface));
  border: 1px solid rgba(var(--v-theme-primary), 0.2);
}

.map-loading {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 600px;
  gap: 16px;
}

.attack-map-container {
  position: relative;
  width: 100%;
  height: 600px;
  background: rgb(var(--v-theme-surface));
  border-radius: 8px;
  overflow: hidden;
}

.attack-map-svg {
  width: 100%;
  height: 100%;
}

:deep(.markers circle) {
  transition: all 0.2s ease;
}
</style>
