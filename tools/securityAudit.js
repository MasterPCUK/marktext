#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const rootDir = path.resolve(process.argv[2] || process.cwd());
const maxFileSize = 1024 * 1024; // 1MB

const includeExtensions = new Set([
  '.js', '.cjs', '.mjs', '.ts', '.tsx', '.vue', '.json', '.css', '.scss', '.sass', '.less',
  '.html', '.htm', '.md', '.txt', '.yaml', '.yml', '.svg'
]);

// Directories dominated by generated assets, documentation, or vendored dependencies.
// Skipping them keeps the signal-to-noise ratio high for the main codebase.
const ignoreDirectories = new Set([
  '.git',
  '.github',
  '.idea',
  '.vscode',
  '.yarn',
  'dist',
  'build',
  'node_modules',
  'docs',
  'test',
  'output',
  'release',
  'releases',
  'static',
  'static/media',
  'vendor'
]);

const allowedUrlPatterns = [
  /^(https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0)(:\\d+)?)/,
  /^https?:\/\/(?:www\.)?w3\.org\//,
  /^https?:\/\/(?:www\.)?w3\.org$/,
  /^https?:\/\/(?:www\.)?github\.com\//,
  /^https?:\/\/(?:raw\.)?githubusercontent\.com\//,
  /^https?:\/\/(?:www\.)?apache\.org\//,
  /^https?:\/\/(?:www\.)?npmjs\.com\//,
  /^https?:\/\/(?:www\.)?nodejs\.org\//,
  /^https?:\/\/(?:www\.)?mozilla\.org\//,
  /^https?:\/\/(?:www\.)?electronjs\.org\//,
  /^https?:\/\/(?:www\.)?bramp\.github\.io\//
];

function isAllowedUrl(url) {
  return allowedUrlPatterns.some(pattern => pattern.test(url));
}

const patterns = [
  {
    type: 'url',
    description: 'External URL reference',
    regex: /(https?:\/\/[^\s\'"`<>]+)/g,
    filter: (match) => {
      return !isAllowedUrl(match);
    }
  },
  {
    type: 'ip',
    description: 'Hard coded IP address',
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    filter: (match) => {
      if (/^(?:0|[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])(?:\.(?:0|[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])){3}$/.test(match)) {
        // Filter out version-like strings such as 1.2.3.4 or 2021.05.12.23
        return !/(?:\d{4}|\d{2})\.\d{2}\.\d{2}\.\d{2}/.test(match);
      }
      return false;
    }
  },
  {
    type: 'hex-escape',
    description: 'Repeated hex escape sequences (possible obfuscation)',
    regex: /(\\x[0-9a-fA-F]{2}){4,}/g
  },
  {
    type: 'base64',
    description: 'Long base64-like string (possible embedded payload)',
    regex: /(?:['"])?([A-Za-z0-9+/]{40,}={0,2})(?:['"])?/g,
    filter: (match, line) => {
      // Skip strings that look like legitimate SVG path data or font data
      if (!/[+=]/.test(match)) {
        return false;
      }

      if (/^[A-Za-z0-9+/]+=*$/.test(match)) {
        const uniqueChars = new Set(match);
        return uniqueChars.size > 10;
      }
      return false;
    }
  }
];

const findings = [];

function isIgnoredDirectory(entryPath) {
  const relative = path.relative(rootDir, entryPath);
  if (!relative || relative === '') {
    return false;
  }

  const parts = relative.split(path.sep);
  return parts.some((segment, index) => {
    const candidate = parts.slice(0, index + 1).join(path.sep);
    return ignoreDirectories.has(segment) || ignoreDirectories.has(candidate);
  });
}

function shouldScanFile(filePath, stats) {
  if (stats.size > maxFileSize) {
    return false;
  }
  const ext = path.extname(filePath).toLowerCase();
  return includeExtensions.has(ext);
}

function scanFile(filePath) {
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (error) {
    return;
  }

  if (content.includes('\u0000')) {
    return;
  }

  const lines = content.split(/\r?\n/);

  lines.forEach((line, lineIndex) => {
    patterns.forEach(pattern => {
      const regex = new RegExp(pattern.regex);
      let matches;
      while ((matches = regex.exec(line)) !== null) {
        const matchText = matches[1] || matches[0];
        const shouldRecord = typeof pattern.filter === 'function' ? pattern.filter(matchText, line) : true;
        if (!shouldRecord) {
          continue;
        }

        const trimmedContext = line.trim();
        const context = trimmedContext.length > 200 ? `${trimmedContext.slice(0, 197)}...` : trimmedContext;

        findings.push({
          type: pattern.type,
          description: pattern.description,
          file: path.relative(rootDir, filePath),
          line: lineIndex + 1,
          match: matchText.trim(),
          context
        });
      }
    });
  });
}

function walkDirectory(directory) {
  let entries;
  try {
    entries = fs.readdirSync(directory, { withFileTypes: true });
  } catch (error) {
    return;
  }

  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);

    if (entry.isDirectory()) {
      if (isIgnoredDirectory(entryPath)) {
        continue;
      }
      walkDirectory(entryPath);
    } else if (entry.isFile()) {
      const stats = fs.statSync(entryPath);
      if (shouldScanFile(entryPath, stats)) {
        scanFile(entryPath);
      }
    }
  }
}

walkDirectory(rootDir);

if (findings.length === 0) {
  console.log('No suspicious patterns detected.');
  process.exit(0);
}

findings.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);

const byType = findings.reduce((acc, item) => {
  if (!acc[item.type]) {
    acc[item.type] = 0;
  }
  acc[item.type] += 1;
  return acc;
}, {});

console.log('Potential security findings:');
console.log('--------------------------------');
for (const finding of findings) {
  console.log(`- [${finding.type}] ${finding.file}:${finding.line}`);
  console.log(`    ${finding.description}`);
  console.log(`    Match: ${finding.match}`);
  if (finding.context && finding.context !== finding.match) {
    console.log(`    Context: ${finding.context}`);
  }
}

console.log('\nSummary by type:');
Object.entries(byType).forEach(([type, count]) => {
  console.log(`  ${type}: ${count}`);
});

process.exit(findings.length ? 1 : 0);
