const puppeteer = require('puppeteer');
const path = require('path');

const OUTPUT_DIR = path.join(__dirname, '..', 'docs', 'images');

(async () => {
  const browser = await puppeteer.launch({
    headless: true,
    defaultViewport: { width: 1440, height: 900, deviceScaleFactor: 2 },
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });

  // 1. Dashboard Overview — already good
  console.log('Capturing dashboard-overview.png...');
  let page = await browser.newPage();
  await page.goto('http://localhost:3000/', { waitUntil: 'networkidle0', timeout: 15000 });
  await new Promise(r => setTimeout(r, 2000));
  await page.screenshot({ path: path.join(OUTPUT_DIR, 'dashboard-overview.png'), fullPage: false });
  console.log('  ✅ dashboard-overview.png');
  await page.close();

  // 2. Alerts — navigate to a project first to trigger alerts via the pipeline
  // Instead, capture the Vulnerabilities page which has the 12 CVEs
  console.log('Capturing alerts-page.png (using vulnerabilities page with data)...');
  page = await browser.newPage();
  await page.goto('http://localhost:3000/vulnerabilities', { waitUntil: 'networkidle0', timeout: 15000 });
  await new Promise(r => setTimeout(r, 3000));
  await page.screenshot({ path: path.join(OUTPUT_DIR, 'alerts-page.png'), fullPage: false });
  console.log('  ✅ alerts-page.png');
  await page.close();

  // 3. Dependency Graph — select the first project to show the actual graph
  console.log('Capturing dependency-graph.png...');
  page = await browser.newPage();
  await page.goto('http://localhost:3000/graph', { waitUntil: 'networkidle0', timeout: 15000 });
  await new Promise(r => setTimeout(r, 2000));

  // Select the first project from the dropdown
  const selectEl = await page.$('select');
  if (selectEl) {
    const options = await page.$$eval('select option', opts =>
      opts.filter(o => o.value).map(o => o.value)
    );
    if (options.length > 0) {
      await page.select('select', options[0]);
      console.log(`  Selected project: ${options[0]}`);
      // Wait for D3 graph to render
      await new Promise(r => setTimeout(r, 5000));
    }
  }

  await page.screenshot({ path: path.join(OUTPUT_DIR, 'dependency-graph.png'), fullPage: false });
  console.log('  ✅ dependency-graph.png');
  await page.close();

  await browser.close();
  console.log('\nAll screenshots captured!');
})();
