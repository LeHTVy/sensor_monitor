<template>
  <v-card class="world-map-card" elevation="2">
    <v-card-title class="d-flex align-center">
      <v-icon icon="mdi-earth" color="primary" class="mr-2" />
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
        <v-progress-circular indeterminate color="primary" />
        <p>Loading attack data...</p>
      </div>

      <div v-else class="attack-map-container">
        <svg ref="mapSvg" class="attack-map-svg"></svg>
      </div>
      
      <!-- Attack Legend -->
      <div v-if="!loading && attacks.length > 0" class="mt-4">
        <div class="text-caption mb-2">Top Attack Origins:</div>
        <v-chip
          v-for="attack in attacks.slice(0, 5)"
          :key="attack.country"
          size="small"
          variant="outlined"
          color="primary"
          class="mr-2 mb-2"
        >
          {{ attack.country }}: {{ attack.count }}
        </v-chip>
      </div>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import * as d3 from 'd3'

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
  'Netherlands': { lat: 52.0, lon: 5.0 },
  'Singapore': { lat: 1.3, lon: 103.8 },
}

async function fetchAttackData() {
  try {
    const response = await fetch(
      `${API_BASE}/logs?limit=100`,
      { headers: { 'X-API-Key': API_KEY } }
    )

    if (response.ok) {
      const data = await response.json()
      const logs = data.logs || []

      // Aggregate attacks by country
      const locationMap = new Map<string, Attack>()

      logs.forEach((log: any) => {
        const country = log.geoip?.country || 'Unknown'
        if (country !== 'Unknown') {
          const existing = locationMap.get(country)
          const coords = countryCoords[country] || { lat: 0, lon: 0 }

          if (existing) {
            existing.count++
          } else {
            locationMap.set(country, {
              ip: log.src_ip || log.ip,
              lat: coords.lat,
              lon: coords.lon,
              country: country,
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

function renderMap() {
  if (!mapSvg.value) return

  const width = 900
  const height = 400

  // Clear existing
  d3.select(mapSvg.value).selectAll('*').remove()

  const svg = d3.select(mapSvg.value)
    .attr('width', '100%')
    .attr('height', height)
    .attr('viewBox', `0 0 ${width} ${height}`)

  // Add world map background with grid
  svg.append('rect')
    .attr('width', width)
    .attr('height', height)
    .attr('fill', 'var(--v-theme-surface)')
    .attr('stroke', 'var(--v-theme-primary)')
    .attr('stroke-width', 1)
    .attr('opacity', 0.1)

  // Draw latitude/longitude grid lines
  const gridGroup = svg.append('g').attr('class', 'grid')
  
  // Horizontal lines (latitudes)
  for (let lat = -90; lat <= 90; lat += 30) {
    const y = ((90 - lat) / 180) * height
    gridGroup.append('line')
      .attr('x1', 0)
      .attr('y1', y)
      .attr('x2', width)
      .attr('y2', y)
      .attr('stroke', 'var(--v-theme-primary)')
      .attr('stroke-width', 0.5)
      .attr('opacity', 0.2)
  }

  // Vertical lines (longitudes)
  for (let lon = -180; lon <= 180; lon += 30) {
    const x = ((lon + 180) / 360) * width
    gridGroup.append('line')
      .attr('x1', x)
      .attr('y1', 0)
      .attr('x2', x)
      .attr('y2', height)
      .attr('stroke', 'var(--v-theme-primary)')
      .attr('stroke-width', 0.5)
      .attr('opacity', 0.2)
  }

  // Convert lat/lon to x/y
  function latLonToXY(lat: number, lon: number) {
    const x = ((lon + 180) / 360) * width
    const y = ((90 - lat) / 180) * height
    return { x, y }
  }

  // Draw attack markers
  const markersGroup = svg.append('g').attr('class', 'markers')

  attacks.value.forEach((attack) => {
    const { x, y } = latLonToXY(attack.lat, attack.lon)
    
    // Outer pulsing circle
    markersGroup.append('circle')
      .attr('cx', x)
      .attr('cy', y)
      .attr('r', 8)
      .attr('fill', 'var(--v-theme-primary)')
      .attr('opacity', 0.3)
      .append('animate')
      .attr('attributeName', 'r')
      .attr('from', 8)
      .attr('to', 25)
      .attr('dur', '2s')
      .attr('repeatCount', 'indefinite')

    markersGroup.append('circle')
      .attr('cx', x)
      .attr('cy', y)
      .attr('r', 8 + (attack.count * 2))
      .attr('fill', 'none')
      .attr('stroke', 'var(--v-theme-primary)')
      .attr('stroke-width', 2)
      .attr('opacity', 0.6)

    // Inner solid circle
    markersGroup.append('circle')
      .attr('cx', x)
      .attr('cy', y)
      .attr('r', 6)
      .attr('fill', 'var(--v-theme-primary)')
      .attr('opacity', 0.9)
      .style('cursor', 'pointer')
      .on('mouseover', function() {
        d3.select(this).attr('r', 9)
      })
      .on('mouseout', function() {
        d3.select(this).attr('r', 6)
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
  background: rgb(var(--v-theme-surface));
  border: 1px solid rgba(var(--v-theme-primary), 0.2);
}

.map-loading {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 400px;
  gap: 16px;
}

.attack-map-container {
  position: relative;
  width: 100%;
  height: 400px;
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
