<template>
  <v-card class="world-map-card" elevation="2">
    <v-card-title class="d-flex align-center">
      <v-icon icon="mdi-earth" color="accent-primary" class="mr-2" />
      <span>ACTIVE CAPTURES</span>
      <v-chip size="small" variant="outlined" class="ml-3">
        {{ attackCount }} attacks
      </v-chip>
      <v-spacer />
      <v-btn size="small" icon variant="text" @click="refresh">
        <v-icon>mdi-refresh</v-icon>
      </v-btn>
    </v-card-title>

    <v-card-text>
      <div v-if="loading" class="map-loading">
        <v-progress-circular indeterminate color="accent-primary" />
        <p>Loading attack data...</p>
      </div>

      <svg v-else ref="mapSvg" class="world-map-svg"></svg>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import * as d3 from 'd3'
import { geoMercator, geoPath } from 'd3-geo'

const API_KEY = 'capture_secure_key_2024'
const API_BASE = '/api'

interface Attack {
  ip: string
  lat: number
  lon: number
  country: string
  count: number
}

const mapSvg = ref<SVGSVGElement>()
const loading = ref(true)
const attackCount = ref(0)
const attacks = ref<Attack[]>([])
let refreshInterval: number | null = null

async function fetchAttackData() {
  try {
    // Fetch logs with GeoIP data
    const response = await fetch(
      `${API_BASE}/logs?limit=100`,
      { headers: { 'X-API-Key': API_KEY } }
    )

    if (response.ok) {
      const data = await response.json()
      const logs = data.logs || []

      // Aggregate attacks by location
      const locationMap = new Map<string, Attack>()

      logs.forEach((log: any) => {
        if (log.geoip && log.geoip.country) {
          const key = `${log.geoip.country}`
          const existing = locationMap.get(key)

          if (existing) {
            existing.count++
          } else {
            // Use approximate coordinates (you can enhance with real lat/lon from API)
            const coords = getCountryCoordinates(log.geoip.country)
            locationMap.set(key, {
              ip: log.src_ip || log.ip,
              lat: coords.lat,
              lon: coords.lon,
              country: log.geoip.country,
              count: 1
            })
          }
        }
      })

      attacks.value = Array.from(locationMap.values())
      attackCount.value = logs.length
    }
  } catch (error) {
    console.error('Error fetching attack data:', error)
  } finally {
    loading.value = false
  }
}

function getCountryCoordinates(country: string): { lat: number; lon: number } {
  // Simple country to coordinates mapping (enhance with real GeoIP data)
  const coords: Record<string, { lat: number; lon: number }> = {
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
  }

  return coords[country] || { lat: 0, lon: 0 }
}

function renderMap() {
  if (!mapSvg.value) return

  const width = 900
  const height = 450

  // Clear existing
  d3.select(mapSvg.value).selectAll('*').remove()

  const svg = d3.select(mapSvg.value)
    .attr('width', '100%')
    .attr('height', height)
    .attr('viewBox', `0 0 ${width} ${height}`)

  // Projection
  const projection = geoMercator()
    .scale(140)
    .translate([width / 2, height / 1.5])

  const path = geoPath().projection(projection)

  // Draw world map (simplified)
  // You can load actual GeoJSON for world countries
  const graticule = d3.geoGraticule()

  svg.append('path')
    .datum(graticule)
    .attr('d', path)
    .attr('fill', 'none')
    .attr('stroke', 'var(--border-color)')
    .attr('stroke-width', 0.5)
    .attr('opacity', 0.3)

  // Draw attack locations
  const g = svg.append('g')

  // Add pulsing circles for attacks
  attacks.value.forEach((attack) => {
    const coords = projection([attack.lon, attack.lat])
    if (!coords) return

    // Outer pulse circle
    g.append('circle')
      .attr('cx', coords[0])
      .attr('cy', coords[1])
      .attr('r', 5)
      .attr('fill', 'var(--accent-primary)')
      .attr('opacity', 0.3)
      .append('animate')
      .attr('attributeName', 'r')
      .attr('from', 5)
      .attr('to', 20)
      .attr('dur', '2s')
      .attr('repeatCount', 'indefinite')

    g.append('circle')
      .attr('cx', coords[0])
      .attr('cy', coords[1])
      .attr('r', 4)
      .attr('fill', 'var(--accent-primary)')
      .attr('opacity', 0.8)
      .style('cursor', 'pointer')
      .on('mouseover', function() {
        d3.select(this).attr('r', 6)
      })
      .on('mouseout', function() {
        d3.select(this).attr('r', 4)
      })
      .append('title')
      .text(`${attack.country}: ${attack.count} attacks`)
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
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  min-height: 500px;
}

.map-loading {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 450px;
  gap: 16px;
}

.world-map-svg {
  width: 100%;
  height: 450px;
  background: var(--bg-secondary);
  border-radius: 8px;
}

:deep(.world-map-svg circle) {
  transition: all 0.2s ease;
}
</style>
