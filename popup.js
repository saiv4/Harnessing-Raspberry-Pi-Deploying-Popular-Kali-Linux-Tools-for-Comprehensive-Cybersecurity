document.getElementById('scan').addEventListener('click', () => {
    document.getElementById('loader').style.display = 'block';

    // Function to fetch basic IP data from Shodan
    async function fetchShodanBasicInfo(ipAddress) {
        const shodanApiKey = 'lb9QFBUlYfkvdTwt8BxZQEUZBCKElPdC'; // Your Shodan API key
        const endpoint = `https://api.shodan.io/shodan/host/${ipAddress}?key=${shodanApiKey}`;

        try {
            const response = await fetch(endpoint);
            if (response.status === 403) {
                console.warn("Shodan API Key is invalid or has exceeded limits.");
                throw new Error('403 Forbidden: Shodan API key invalid or rate limit reached.');
            }
            if (!response.ok) {
                throw new Error(`Error fetching Shodan data: ${response.status} ${response.statusText}`);
            }

            const data = await response.json();
            return {
                ipAddress: ipAddress,
                country: data.country_name || 'N/A',
                org: data.org || 'N/A',
                isp: data.isp || 'N/A',
                ports: data.ports ? data.ports.join(', ') : 'None',
            };
        } catch (error) {
            console.error("Shodan Error:", error);
            return { error: error.message };
        }
    }

    // Function to fetch public IP information (fallback for Shodan)
    async function fetchIPInfoFallback(ipAddress) {
        const endpoint = `https://ipinfo.io/${ipAddress}/json`;

        try {
            const response = await fetch(endpoint);
            if (!response.ok) {
                throw new Error(`Error fetching IPInfo data: ${response.status} ${response.statusText}`);
            }

            const data = await response.json();
            return {
                ipAddress: data.ip || 'N/A',
                country: data.country || 'N/A',
                region: data.region || 'N/A',
                city: data.city || 'N/A',
            };
        } catch (error) {
            console.error("IPInfo Error:", error);
            return { error: error.message };
        }
    }

    // Function to fetch data from Netcraft
    async function fetchNetcraftInfo(domain) {
        try {
            const response = await fetch(`https://sitereport.netcraft.com/?url=${domain}`, {
                headers: {
                    'User-Agent':
                        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
                },
            });

            if (!response.ok) {
                throw new Error(`Netcraft Error: ${response.status} ${response.statusText}`);
            }

            const html = await response.text();
            console.log("Netcraft HTML Response:", html); // Debugging HTML response
            return html; // Return raw HTML
        } catch (error) {
            console.error("Netcraft Error:", error);
            return { error: error.message };
        }
    }

    // Function to extract data from Netcraft's HTML response
    function extractNetcraftInfo(html) {
        const hostingInfo = html.match(/<th>Hosting company<\/th>\s*<td>(.*?)<\/td>/)?.[1] || 'N/A';
        const hostingCountry = html.match(/<th>Hosting country<\/th>\s*<td>.*?<span id='advertised_country'>(.*?)<\/span>/)?.[1] || 'N/A';
        const ipAddress = html.match(/<th>IPv4 address<\/th>\s*<td><span id="ip_address">(.*?)<\/span>/)?.[1] || 'N/A';

        return { hostingInfo, hostingCountry, ipAddress };
    }

    // Main scanning logic
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
        const url = new URL(tabs[0].url).hostname; // Extract domain from URL
        const resultsDiv = document.getElementById('results');
        resultsDiv.innerHTML = `<p>Scanning URL: ${url}</p>`;

        try {
            // Step 1: VirusTotal API Logic
            const apiKey = '627362e95f78eef68d7b75ad8ee2b5c699f7a1f3dace98f9a5f99b66757556d5'; // VirusTotal API key
            const apiEndpoint = `https://www.virustotal.com/api/v3/urls`;
            const urlIdResponse = await fetch(apiEndpoint, {
                method: 'POST',
                headers: {
                    'x-apikey': apiKey,
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `url=${encodeURIComponent(url)}`,
            });

            if (!urlIdResponse.ok) {
                throw new Error(`Error fetching VirusTotal data: ${urlIdResponse.status} ${urlIdResponse.statusText}`);
            }

            const urlIdData = await urlIdResponse.json();
            const analysisId = urlIdData.data.id;

            const scanResultsEndpoint = `https://www.virustotal.com/api/v3/analyses/${analysisId}`;
            const scanResultsResponse = await fetch(scanResultsEndpoint, {
                headers: { 'x-apikey': apiKey },
            });

            const scanResults = await scanResultsResponse.json();
            const stats = scanResults.data?.attributes?.stats;
            resultsDiv.innerHTML += `
                <p><strong>VirusTotal Results:</strong></p>
                <ul>
                    <li style="color: red;">Malicious: ${stats.malicious}</li>
                    <li style="color: green;">Harmless: ${stats.harmless}</li>
                    <li style="color: orange;">Suspicious: ${stats.suspicious}</li>
                    <li>Undetected: ${stats.undetected}</li>
                </ul>
            `;

            // Step 2: Fetch Shodan Information
            const ipAddress = "208.80.154.224"; // Example IP
            let shodanData = await fetchShodanBasicInfo(ipAddress);
            if (shodanData.error) {
                console.warn("Shodan failed. Trying IPInfo...");
                shodanData = await fetchIPInfoFallback(ipAddress);
            }

            resultsDiv.innerHTML += `
                <p><strong>Shodan (or Fallback) Results:</strong></p>
                <ul>
                    <li><strong>IP Address:</strong> ${shodanData.ipAddress}</li>
                    <li><strong>Country:</strong> ${shodanData.country}</li>
                    <li><strong>Region:</strong> ${shodanData.region || 'N/A'}</li>
                </ul>
            `;

            // Step 3: Fetch and Display Netcraft Information
            const netcraftHtml = await fetchNetcraftInfo(url);
            const netcraftData = extractNetcraftInfo(netcraftHtml);
            resultsDiv.innerHTML += `
                <p><strong>Netcraft Information:</strong></p>
                <ul>
                    <li><strong>Hosting Company:</strong> ${netcraftData.hostingInfo}</li>
                    <li><strong>Hosting Country:</strong> ${netcraftData.hostingCountry}</li>
                    <li><strong>IPv4 Address:</strong> ${netcraftData.ipAddress}</li>
                </ul>
            `;
        } catch (error) {
            resultsDiv.innerHTML += `<p style="color: red;">Error: ${error.message}</p>`;
            console.error("Error occurred:", error);
        } finally {
            document.getElementById('loader').style.display = 'none';
        }
    });
});