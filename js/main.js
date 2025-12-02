const API_KEY = 'YOUR API KEY HERE'

const getElement = id => document.getElementById(id)

function switchTab(tab) {
	document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'))
	document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'))

	event.target.closest('.tab-btn').classList.add('active')
	getElement(tab + 'Tab').classList.add('active')

	getElement('result').style.display = 'none'
}

function updateFileName(input) {
	const fileName = input.files[0]?.name || 'Nie wybrano pliku'
	getElement('fileName').textContent = fileName
}

const updateResult = (content, display = true) => {
	const result = getElement('result')
	result.style.display = display ? 'block' : 'none'
	result.innerHTML = content
}

const showLoading = message =>
	updateResult(`
        <div class="loading">
            <div class="spinner"></div>
            <p>${message}</p>
        </div>
`)

const showError = message => updateResult(`<p class="error"><i class="fas fa-circle-exclamation"></i> ${message}</p>`)

async function makeRequest(url, options = {}) {
	const response = await fetch(url, {
		...options,
		headers: {
			'x-apikey': API_KEY,
			...options.headers,
		},
	})

	if (!response.ok) {
		const error = await response.json().catch(() => ({ error: { message: response.statusText } }))
		throw new Error(error.error?.message || 'Request failed!')
	}

	return response.json()
}

async function scanURL() {
	const url = getElement('urlInput').value.trim()
	if (!url) return showError('Proszę wprowadzić adres URL!')

	try {
		new URL(url)
	} catch {
		return showError('Proszę wprowadzić poprawny adres URL (np. https://example.com)')
	}

	try {
		showLoading('Przesyłanie URL do skanowania...')

		const encodedUrl = encodeURIComponent(url)

		const submitResult = await makeRequest('https://www.virustotal.com/api/v3/urls', {
			method: 'POST',
			headers: {
				accept: 'application/json',
				'content-type': 'application/x-www-form-urlencoded',
			},
			body: `url=${encodedUrl}`,
		})

		if (!submitResult.data?.id) {
			throw new Error('Nie udało się uzyskać ID analizy')
		}

		await new Promise(resolve => setTimeout(resolve, 3000))

		showLoading('Pobieranie wyników skanowania...')
		await pollAnalysisResults(submitResult.data.id)
	} catch (error) {
		showError(`Błąd: ${error.message}`)
	}
}

async function scanFile() {
	const file = getElement('fileInput').files[0]
	if (!file) return showError('Proszę wybrać plik!')
	if (file.size > 32 * 1024 * 1024) return showError('Rozmiar pliku przekracza limit 32MB.')

	try {
		showLoading('Przesyłanie pliku...')

		const formData = new FormData()
		formData.append('file', file)

		const uploadResult = await makeRequest('https://www.virustotal.com/api/v3/files', {
			method: 'POST',
			body: formData,
		})

		if (!uploadResult.data?.id) {
			throw new Error('Nie udało się przesłać pliku!')
		}

		await new Promise(resolve => setTimeout(resolve, 3000))

		showLoading('Pobieranie wyników skanowania...')
		const analysisResult = await makeRequest(`https://www.virustotal.com/api/v3/analyses/${uploadResult.data.id}`)

		if (!analysisResult.data?.id) {
			throw new Error('Nie udało się uzyskać wyników analizy!')
		}

		await pollAnalysisResults(analysisResult.data.id, file.name)
	} catch (error) {
		showError(`Błąd: ${error.message}`)
	}
}

async function pollAnalysisResults(analysisId, fileName = '') {
	const maxAttempts = 20
	let attempts = 0
	let interval = 2000

	while (attempts < maxAttempts) {
		try {
			showLoading(
				`Analizowanie${fileName ? ` ${fileName}` : ''}... (pozostało ${(
					((maxAttempts - attempts) * interval) /
					1000
				).toFixed(0)}s)`
			)

			const report = await makeRequest(`https://www.virustotal.com/api/v3/analyses/${analysisId}`)
			const status = report.data?.attributes?.status

			if (!status) throw new Error('Nieprawidłowa odpowiedź analizy!')

			if (status === 'completed') {
				showFormattedResult(report)
				break
			}

			if (status === 'failed') {
				throw new Error('Analiza nie powiodła się!')
			}

			if (++attempts >= maxAttempts) {
				throw new Error('Przekroczono limit czasu analizy - spróbuj ponownie!')
			}

			interval = Math.min(interval * 1.5, 8000)
			await new Promise(resolve => setTimeout(resolve, interval))
		} catch (error) {
			showError(`Błąd: ${error.message}`)
			break
		}
	}
}

function showFormattedResult(data) {
	if (!data?.data?.attributes?.stats) return showError('Nieprawidłowy format odpowiedzi!')

	const stats = data.data.attributes.stats
	const total = Object.values(stats).reduce((sum, val) => sum + val, 0)
	if (!total) return showError('Brak dostępnych wyników analizy!')

	const getPercent = val => ((val / total) * 100).toFixed(1)

	const categories = {
		malicious: { color: 'malicious', label: 'Złośliwe', icon: 'fa-skull-crossbones' },
		suspicious: { color: 'suspicious', label: 'Podejrzane', icon: 'fa-triangle-exclamation' },
		harmless: { color: 'safe', label: 'Bezpieczne', icon: 'fa-shield-check' },
		undetected: { color: 'undetected', label: 'Nie wykryto', icon: 'fa-question' },
	}

	const percents = Object.keys(categories).reduce((acc, key) => {
		acc[key] = getPercent(stats[key])
		return acc
	}, {})

	const verdict = stats.malicious > 0 ? 'Zagrożenie!' : stats.suspicious > 0 ? 'Podejrzane' : 'Bezpieczne'
	const verdictClass = stats.malicious > 0 ? 'malicious' : stats.suspicious > 0 ? 'suspicious' : 'safe'
	const verdictIcon =
		stats.malicious > 0 ? 'fa-circle-xmark' : stats.suspicious > 0 ? 'fa-circle-exclamation' : 'fa-circle-check'

	updateResult(`
        <h3><i class="fas fa-chart-pie"></i> Raport Skanowania</h3>
        <div class="scan-stats">
            <p><strong>Wynik:</strong> <span class="${verdictClass}"><i class="fas ${verdictIcon}"></i> ${verdict}</span></p>
            <div class="progress-section">
                <div class="progress-label">
                    <span><i class="fas fa-magnifying-glass-chart"></i> Wyniki Detekcji</span>
                    <span class="progress-percent">${percents.malicious}% Wykryto zagrożeń</span>
                </div>
                <div class="progress-stacked">
                    ${Object.entries(categories)
											.map(
												([key, { color }]) => `
                        <div class="progress-bar ${color}" style="width: ${percents[key]}%" title="${categories[key].label}: ${stats[key]} (${percents[key]}%)">
                            <span class="progress-label-overlay">${stats[key]}</span>
                        </div>
                    `
											)
											.join('')}
                </div>
                <div class="progress-legend">
                    ${Object.entries(categories)
											.map(
												([key, { color, label, icon }]) => `
                        <div class="legend-item">
                            <span class="legend-color ${color}"></span>
                            <span><i class="fas ${icon}"></i> ${label} (${percents[key]}%)</span>
                        </div>
                    `
											)
											.join('')}
                </div>
            </div>
            <div class="detection-details">
                ${Object.entries(categories)
									.map(
										([key, { color, label, icon }]) => `
                    <div class="detail-item ${color}">
                        <span class="detail-label"><i class="fas ${icon}"></i> ${label}</span>
                        <span class="detail-value">${stats[key]}</span>
                        <span class="detail-percent">${percents[key]}%<span>
                    </div>
                `
									)
									.join('')}
            </div>
        </div>
        <button class="scan-btn" onclick="showFullReport(this.getAttribute('data-report'))" data-report='${JSON.stringify(
					data
				)}'>
			<i class="fas fa-file-lines"></i>
			<span>Zobacz Pełny Raport</span>
			<div class="btn-shine"></div>
		</button>
    `)

	setTimeout(() => getElement('result').querySelector('.progress-stacked').classList.add('animate'), 100)
}

function showFullReport(reportData) {
	const data = typeof reportData === 'string' ? JSON.parse(reportData) : reportData
	const modal = getElement('fullReportModal')
	const results = data.data?.attributes?.results

	const categoryLabels = {
		malicious: 'Złośliwe',
		suspicious: 'Podejrzane',
		harmless: 'Bezpieczne',
		undetected: 'Nie wykryto',
		'type-unsupported': 'Nieobsługiwane',
		timeout: 'Przekroczono czas',
	}

	const categoryIcons = {
		malicious: 'fa-skull-crossbones',
		suspicious: 'fa-triangle-exclamation',
		harmless: 'fa-shield-check',
		undetected: 'fa-question',
		'type-unsupported': 'fa-ban',
		timeout: 'fa-clock',
	}

	getElement('fullReportContent').innerHTML = `
        ${
					results
						? `
            <table>
                <thead>
					<tr>
						<th><i class="fas fa-microchip"></i> Silnik Antywirusowy</th>
						<th><i class="fas fa-chart-simple"></i> Wynik</th>
					</tr>
				</thead>
				<tbody>
                ${Object.entries(results)
									.map(([engine, { category }]) => {
										const categoryClass =
											category === 'malicious' ? 'malicious' : category === 'suspicious' ? 'suspicious' : 'safe'
										const label = categoryLabels[category] || category
										const icon = categoryIcons[category] || 'fa-circle'
										return `
                    <tr>
                        <td><i class="fas fa-shield"></i> ${engine}</td>
                        <td class="${categoryClass}"><i class="fas ${icon}"></i> ${label}</td>
                    </tr>
                `
									})
									.join('')}
				</tbody>
            </table>
        `
						: '<p class="error"><i class="fas fa-circle-exclamation"></i> Brak szczegółowych wyników!</p>'
				}
    `

	modal.style.display = 'block'
	requestAnimationFrame(() => modal.classList.add('show'))
}

const closeModal = () => {
	const modal = getElement('fullReportModal')
	modal.classList.remove('show')
	setTimeout(() => (modal.style.display = 'none'), 300)
}

window.addEventListener('load', () => {
	const modal = getElement('fullReportModal')
	window.addEventListener('click', e => e.target === modal && closeModal())
})
