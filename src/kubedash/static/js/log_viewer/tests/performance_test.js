/**
 * Performance test for LogViewer with 10,000-log-line buffer and high-throughput simulated stream.
 * 
 * Run this test in a browser console to validate performance:
 * 1. Load the enhanced log viewer page
 * 2. Open browser DevTools console
 * 3. Paste and run this script
 * 4. Review results in console
 */
(function runPerformanceTest() {
  console.log('=== Enhanced Log Viewer Performance Test ===\n');

  const TEST_CONFIG = {
    totalLines: 10000,
    batchSize: 100,
    intervalMs: 10,
    maxDomNodes: 5000
  };

  const results = {
    startTime: null,
    endTime: null,
    totalLinesAdded: 0,
    avgAddTimeMs: 0,
    peakMemoryMB: 0,
    domNodeCount: 0,
    renderTimeMs: 0,
    filterTimeMs: 0
  };

  // Test data generator
  const levels = ['DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL'];
  const levelWeights = [0.3, 0.4, 0.15, 0.1, 0.05]; // Weighted distribution
  
  function randomLevel() {
    const r = Math.random();
    let cumulative = 0;
    for (let i = 0; i < levels.length; i++) {
      cumulative += levelWeights[i];
      if (r <= cumulative) return levels[i];
    }
    return 'UNKNOWN';
  }

  function generateLogLine(index) {
    const level = randomLevel();
    const timestamp = new Date(Date.now() - (TEST_CONFIG.totalLines - index) * 100).toISOString();
    const messages = {
      DEBUG: `Processing request #${index} with payload size: ${Math.floor(Math.random() * 10000)} bytes`,
      INFO: `Request completed successfully in ${Math.floor(Math.random() * 500)}ms`,
      WARN: `High memory usage detected: ${Math.floor(Math.random() * 100)}%`,
      ERROR: `Failed to process request: connection timeout after ${Math.floor(Math.random() * 30000)}ms`,
      FATAL: `OutOfMemoryError: Java heap space`
    };
    return `[${timestamp}] ${level} [main] ${messages[level]}`;
  }

  // Test 1: Buffer Performance
  console.log('Test 1: Buffer Performance (adding 10,000 lines)');
  const buffer = new LogBuffer(TEST_CONFIG.totalLines);
  const addTimes = [];

  const bufferStart = performance.now();
  for (let i = 0; i < TEST_CONFIG.totalLines; i++) {
    const start = performance.now();
    buffer.add(generateLogLine(i));
    const end = performance.now();
    addTimes.push(end - start);
  }
  const bufferEnd = performance.now();

  results.totalLinesAdded = buffer.totalReceived;
  results.avgAddTimeMs = addTimes.reduce((a, b) => a + b, 0) / addTimes.length;
  console.log(`  ✓ Added ${results.totalLinesAdded} lines in ${(bufferEnd - bufferStart).toFixed(2)}ms`);
  console.log(`  ✓ Average add time: ${results.avgAddTimeMs.toFixed(4)}ms per line`);
  console.log(`  ✓ Buffer utilization: ${buffer.getUtilization().current} / ${buffer.getUtilization().max} lines`);
  console.log(`  ✓ Evicted lines: ${buffer.getUtilization().evicted}`);
  console.log('');

  // Test 2: Filter Performance
  console.log('Test 2: Filter Performance (filtering 10,000 lines)');
  const filter = new LogFilter();
  const filterTimes = [];

  // Test filtering by level
  const testLevels = [['ERROR'], ['ERROR', 'WARN'], ['INFO', 'WARN', 'ERROR'], ['DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL', 'UNKNOWN']];
  
  for (const activeLevels of testLevels) {
    filter.setLevels(activeLevels);
    const start = performance.now();
    const filtered = buffer.getFilteredLines(filter);
    const end = performance.now();
    filterTimes.push(end - start);
    console.log(`  ✓ Filter [${activeLevels.join(', ')}]: ${filtered.length} lines in ${(end - start).toFixed(2)}ms`);
  }

  results.filterTimeMs = Math.max(...filterTimes);
  console.log(`  ✓ Max filter time: ${results.filterTimeMs.toFixed(2)}ms`);
  console.log('');

  // Test 3: Level Detector Performance
  console.log('Test 3: Level Detector Performance (10,000 detections)');
  const detectorStart = performance.now();
  const detectionResults = { DEBUG: 0, INFO: 0, WARN: 0, ERROR: 0, FATAL: 0, UNKNOWN: 0 };
  
  for (let i = 0; i < buffer.lines.length; i++) {
    const level = LogLevelDetector.detect(buffer.lines[i].line);
    detectionResults[level]++;
  }
  const detectorEnd = performance.now();

  console.log(`  ✓ Detected levels in ${(detectorEnd - detectorStart).toFixed(2)}ms`);
  console.log(`  ✓ Distribution:`, detectionResults);
  console.log('');

  // Test 4: Memory Usage
  console.log('Test 4: Memory Usage');
  if (performance.memory) {
    const memoryMB = performance.memory.usedJSHeapSize / 1024 / 1024;
    results.peakMemoryMB = memoryMB;
    console.log(`  ✓ Used heap: ${memoryMB.toFixed(2)} MB`);
    console.log(`  ✓ Total heap: ${(performance.memory.totalJSHeapSize / 1024 / 1024).toFixed(2)} MB`);
    console.log(`  ✓ Heap limit: ${(performance.memory.jsHeapSizeLimit / 1024 / 1024).toFixed(2)} MB`);
  } else {
    console.log('  ⚠ Memory API not available in this browser');
  }
  console.log('');

  // Test 5: Simulated High-Throughput Stream
  console.log('Test 5: Simulated High-Throughput Stream (100 lines/batch, 10ms interval)');
  const streamBuffer = new LogBuffer(10000);
  let linesAdded = 0;
  const streamStart = performance.now();
  
  function addBatch() {
    for (let i = 0; i < TEST_CONFIG.batchSize && linesAdded < 5000; i++) {
      streamBuffer.add(generateLogLine(linesAdded));
      linesAdded++;
    }
    
    if (linesAdded < 5000) {
      setTimeout(addBatch, TEST_CONFIG.intervalMs);
    } else {
      const streamEnd = performance.now();
      const duration = streamEnd - streamStart;
      const throughput = linesAdded / (duration / 1000);
      
      console.log(`  ✓ Added ${linesAdded} lines in ${duration.toFixed(2)}ms`);
      console.log(`  ✓ Throughput: ${throughput.toFixed(0)} lines/second`);
      console.log(`  ✓ Buffer size: ${streamBuffer.lines.length} lines`);
      console.log('');
      
      // Final Summary
      printSummary();
    }
  }
  
  addBatch();

  function printSummary() {
    console.log('=== Performance Test Summary ===\n');
    console.log(`Total lines processed: ${results.totalLinesAdded}`);
    console.log(`Average add time: ${results.avgAddTimeMs.toFixed(4)}ms`);
    console.log(`Max filter time: ${results.filterTimeMs.toFixed(2)}ms`);
    if (results.peakMemoryMB > 0) {
      console.log(`Peak memory: ${results.peakMemoryMB.toFixed(2)} MB`);
    }
    console.log('');

    // Pass/Fail criteria
    const passed = [];
    const failed = [];

    if (results.avgAddTimeMs < 1) {
      passed.push('Buffer add time < 1ms');
    } else {
      failed.push(`Buffer add time >= 1ms (${results.avgAddTimeMs.toFixed(4)}ms)`);
    }

    if (results.filterTimeMs < 50) {
      passed.push('Filter time < 50ms');
    } else {
      failed.push(`Filter time >= 50ms (${results.filterTimeMs.toFixed(2)}ms)`);
    }

    if (results.peakMemoryMB > 0 && results.peakMemoryMB < 500) {
      passed.push('Memory usage < 500MB');
    } else if (results.peakMemoryMB > 0) {
      failed.push(`Memory usage >= 500MB (${results.peakMemoryMB.toFixed(2)} MB)`);
    }

    console.log(`Passed: ${passed.length}`);
    passed.forEach(p => console.log(`  ✓ ${p}`));
    console.log('');
    
    if (failed.length > 0) {
      console.log(`Failed: ${failed.length}`);
      failed.forEach(f => console.log(`  ✗ ${f}`));
    }

    console.log('\n=== Test Complete ===');
  }
})();
