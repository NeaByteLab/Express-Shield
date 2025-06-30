const fs = require('fs')
const path = require('path')
const https = require('https')

/**
 * Parse Cloudflare IPs from JSON API (page-data.json)
 * Params: ApiJson
 */
function parseCloudflareIps(json) {
  const blades = json.result?.data?.page?.relatedBlades || []
  const features = blades.find(b => Array.isArray(b.features))?.features || []
  let ipv4 = []
  let ipv6 = []
  features.forEach(feat => {
    if (feat.title === 'IPv4') {
      ipv4 = feat.description
        .split('\n')
        .map(x => x.replace(/<[^>]+>/g, '').replace('- ', '').trim())
        .filter(x => /^\d+\.\d+\.\d+\.\d+\/\d+$/.test(x))
    }
    if (feat.title === 'IPv6') {
      ipv6 = feat.description
        .split('\n')
        .map(x => x.replace(/<[^>]+>/g, '').replace('- ', '').trim())
        .filter(x => /^[a-fA-F0-9:]+\/\d+$/.test(x))
    }
  })
  return { ipv4, ipv6 }
}

/**
 * Download & Update Cloudflare IPs to ./data/
 * Params: OutputDir
 */
function updateCloudflareIpsFromPageData(outputDir = path.join(__dirname, '../data')) {
  const apiUrl = 'https://www.cloudflare.com/page-data/ips/page-data.json'
  https.get(apiUrl, res => {
    let data = ''
    res.on('data', chunk => { data += chunk })
    res.on('end', () => {
      try {
        const json = JSON.parse(data)
        const { ipv4, ipv6 } = parseCloudflareIps(json)
        if (!fs.existsSync(outputDir)) { fs.mkdirSync(outputDir, { recursive: true }) }
        fs.writeFileSync(path.join(outputDir, 'cloudflare_ipv4.json'), JSON.stringify(ipv4, null, 2))
        fs.writeFileSync(path.join(outputDir, 'cloudflare_ipv6.json'), JSON.stringify(ipv6, null, 2))
      } catch (err) {
        throw new Error('Parse error: ' + err.message)
      }
    })
  }).on('error', err => {
    throw new Error('Failed to fetch: ' + apiUrl + ' ' + err.message)
  })
}

/**
 * Auto Update If Run Directly Or Required
 */
function scheduleUpdateOnFirstRequire() {
  const marker = path.join(__dirname, '../data/.cfips-init')
  if (!(fs.existsSync(marker))) {
    try {
      updateCloudflareIpsFromPageData()
      fs.writeFileSync(marker, String(Date.now()))
    } catch (err) {
      throw err
    }
  }
}

// Run if main or if required for the first time in app
if (require.main === module) {
  try {
    updateCloudflareIpsFromPageData()
  } catch (err) {
    throw err
  }
} else {
  scheduleUpdateOnFirstRequire()
}

module.exports = {
  updateCloudflareIpsFromPageData
}