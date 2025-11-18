let orderbookData = null;
let sortColumn = 'fidelity_bond_value';
let sortDirection = 'desc';

const OFFER_TYPE_NAMES = {
    'sw0absoffer': 'SW0 Absolute',
    'sw0reloffer': 'SW0 Relative',
    'swabsoffer': 'SWA Absolute',
    'swreloffer': 'SWA Relative'
};

const DIRECTORY_COLORS = [
    '#3498db', '#e74c3c', '#2ecc71', '#f39c12', '#9b59b6',
    '#1abc9c', '#e67e22', '#34495e', '#16a085', '#c0392b',
    '#8e44ad', '#d35400', '#27ae60', '#2980b9', '#f1c40f'
];

function getDirectoryAbbreviation(node) {
    const parts = node.split(':')[0].split('.');
    if (parts.length > 1) {
        return parts[0].substring(0, 3).toUpperCase();
    }
    return node.substring(0, 3).toUpperCase();
}

function getDirectoryColor(node) {
    let hash = 0;
    for (let i = 0; i < node.length; i++) {
        hash = ((hash << 5) - hash) + node.charCodeAt(i);
        hash = hash & hash;
    }
    return DIRECTORY_COLORS[Math.abs(hash) % DIRECTORY_COLORS.length];
}

async function fetchOrderbook() {
    try {
        const response = await fetch('/orderbook.json');
        orderbookData = await response.json();
        updateStats();
        updateDirectoryBreakdown();
        updateDirectoryFilter();
        renderTable();
        updateLastUpdate();
    } catch (error) {
        console.error('Failed to fetch orderbook:', error);
    }
}

function updateStats() {
    if (!orderbookData) return;

    const bondsCount = orderbookData.offers.filter(o => o.fidelity_bond_data).length;

    document.getElementById('total-offers').textContent = orderbookData.offers.length;
    document.getElementById('directory-nodes').textContent = orderbookData.directory_nodes.length;
    document.getElementById('fidelity-bonds').textContent = bondsCount;
}

function updateDirectoryBreakdown() {
    if (!orderbookData) return;

    const breakdown = document.getElementById('directory-breakdown');
    breakdown.innerHTML = '';

    const stats = orderbookData.directory_stats || {};

    const sortedEntries = Object.entries(stats).sort((a, b) => b[1].offer_count - a[1].offer_count);

    sortedEntries.forEach(([node, data]) => {
        const item = document.createElement('div');
        item.className = 'directory-item';

        const nameContainer = document.createElement('div');
        nameContainer.className = 'directory-name-container';

        const abbr = getDirectoryAbbreviation(node);
        const color = getDirectoryColor(node);
        const badge = document.createElement('span');
        badge.className = 'dir-badge';
        badge.style.backgroundColor = color;
        badge.textContent = abbr;
        badge.title = node;

        const statusIcon = document.createElement('span');
        statusIcon.className = 'status-icon';
        if (data.connected) {
            statusIcon.className = 'status-icon status-connected';
            statusIcon.textContent = '●';
            statusIcon.title = 'Connected';
        } else if (data.connection_attempts > 0) {
            statusIcon.className = 'status-icon status-disconnected';
            statusIcon.textContent = '●';
            statusIcon.title = 'Disconnected';
        } else {
            statusIcon.className = 'status-icon status-not-attempted';
            statusIcon.textContent = '●';
            statusIcon.title = 'Not attempted';
        }

        const name = document.createElement('span');
        name.className = 'directory-name';
        name.textContent = node;

        nameContainer.appendChild(statusIcon);
        nameContainer.appendChild(badge);
        nameContainer.appendChild(name);

        const infoContainer = document.createElement('div');
        infoContainer.className = 'directory-info';

        const count = document.createElement('span');
        count.className = 'directory-count';
        count.textContent = `${data.offer_count} offers`;
        infoContainer.appendChild(count);

        if (data.uptime_percentage !== undefined) {
            const uptime = document.createElement('span');
            uptime.className = 'directory-uptime';
            uptime.textContent = `${data.uptime_percentage}% uptime`;
            uptime.title = `${data.successful_connections} successful connections`;
            infoContainer.appendChild(uptime);
        }

        item.appendChild(nameContainer);
        item.appendChild(infoContainer);
        breakdown.appendChild(item);
    });
}

function updateDirectoryFilter() {
    if (!orderbookData) return;

    const select = document.getElementById('filter-directory');
    const currentValue = select.value;

    select.innerHTML = '<option value="">All</option>';

    orderbookData.directory_nodes.forEach(node => {
        const option = document.createElement('option');
        option.value = node;
        option.textContent = node;
        select.appendChild(option);
    });

    select.value = currentValue;
}

function updateLastUpdate() {
    if (!orderbookData) return;

    const timestamp = new Date(orderbookData.timestamp);
    const formatted = timestamp.toLocaleString();
    document.getElementById('last-update').textContent = `Last update: ${formatted}`;
}

function filterOffers() {
    if (!orderbookData) return [];

    const filterDirectory = document.getElementById('filter-directory').value;
    const searchText = document.getElementById('search-counterparty').value.toLowerCase();

    return orderbookData.offers.filter(offer => {
        if (filterDirectory && !offer.directory_nodes.includes(filterDirectory)) return false;

        if (searchText && !offer.counterparty.toLowerCase().includes(searchText)) return false;

        return true;
    });
}

function sortOffers(offers) {
    const sorted = [...offers];

    sorted.sort((a, b) => {
        let aVal = a[sortColumn];
        let bVal = b[sortColumn];

        if (sortColumn === 'fidelity_bond_value') {
            const aHasBondData = a.fidelity_bond_data ? true : false;
            const bHasBondData = b.fidelity_bond_data ? true : false;
            const aHasValue = a.fidelity_bond_value > 0;
            const bHasValue = b.fidelity_bond_value > 0;

            const aCategory = aHasValue ? 0 : (aHasBondData ? 1 : 2);
            const bCategory = bHasValue ? 0 : (bHasBondData ? 1 : 2);

            if (aCategory !== bCategory) {
                return sortDirection === 'asc'
                    ? bCategory - aCategory
                    : aCategory - bCategory;
            }

            if (aCategory === 0) {
                aVal = a.fidelity_bond_value;
                bVal = b.fidelity_bond_value;
            } else {
                return 0;
            }
        } else if (sortColumn === 'cjfee') {
            const aIsAbsolute = a.ordertype.includes('absoffer');
            const bIsAbsolute = b.ordertype.includes('absoffer');

            if (aIsAbsolute !== bIsAbsolute) {
                return sortDirection === 'asc'
                    ? (aIsAbsolute ? -1 : 1)
                    : (aIsAbsolute ? 1 : -1);
            }

            aVal = parseFloat(aVal);
            bVal = parseFloat(bVal);
        } else if (typeof aVal === 'string') {
            aVal = aVal.toLowerCase();
            bVal = bVal.toLowerCase();
        }

        if (sortDirection === 'asc') {
            return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
        } else {
            return aVal < bVal ? 1 : aVal > bVal ? -1 : 0;
        }
    });

    return sorted;
}

function formatFee(offer) {
    const isAbsolute = offer.ordertype.includes('absoffer');

    if (isAbsolute) {
        return `${offer.cjfee} sats`;
    } else {
        const percentage = (parseFloat(offer.cjfee) * 100).toFixed(4);
        return `${percentage}%`;
    }
}

function formatNumber(num) {
    return num.toLocaleString();
}

function showBondModal(bondData, bondAmount) {
    const modal = document.getElementById('bond-modal');
    if (!modal) return;

    document.getElementById('bond-maker-nick').textContent = bondData.maker_nick;

    const mempoolUrl = orderbookData.mempool_url || 'https://mempool.space';
    const txidElement = document.getElementById('bond-txid');
    txidElement.innerHTML = `<a href="${mempoolUrl}/tx/${bondData.utxo_txid}" target="_blank">${bondData.utxo_txid}</a>`;

    document.getElementById('bond-vout').textContent = bondData.utxo_vout;

    if (bondAmount > 0) {
        const btcAmount = (bondAmount / 100000000).toFixed(8);
        document.getElementById('bond-amount').textContent = `${formatNumber(bondAmount)} sats (${btcAmount} BTC)`;
    } else {
        document.getElementById('bond-amount').textContent = 'Pending...';
    }

    document.getElementById('bond-locktime').textContent = new Date(bondData.locktime * 1000).toISOString();
    document.getElementById('bond-utxo-pub').textContent = bondData.utxo_pub;
    document.getElementById('bond-cert-expiry').textContent = bondData.cert_expiry;
    document.getElementById('bond-redeem-script').textContent = bondData.redeem_script || 'N/A';
    document.getElementById('bond-p2wsh-script').textContent = bondData.p2wsh_script || 'N/A';

    document.getElementById('rpc-decodescript').textContent =
        `bitcoin-cli decodescript ${bondData.redeem_script || '<redeem_script>'}`;
    document.getElementById('rpc-gettxout').textContent =
        `bitcoin-cli gettxout ${bondData.utxo_txid} ${bondData.utxo_vout}`;

    modal.style.display = 'block';
}

function renderTable() {
    const tbody = document.getElementById('orderbook-tbody');
    const fragment = document.createDocumentFragment();

    const filtered = filterOffers();
    const sorted = sortOffers(filtered);

    sorted.forEach(offer => {
        const row = document.createElement('tr');

        const typeClass = offer.ordertype.startsWith('sw0') ? 'type-sw0' : 'type-swa';
        const feeClass = offer.ordertype.includes('absoffer') ? 'fee-absolute' : 'fee-relative';

        let hasBond = '';
        let bondValue;
        if (offer.fidelity_bond_value > 0) {
            hasBond = 'bond-value-clickable';
            bondValue = formatNumber(Math.round(offer.fidelity_bond_value));
        } else if (offer.fidelity_bond_data) {
            hasBond = 'bond-value-clickable';
            const bondAmount = orderbookData.fidelitybonds.find(
                b => b.counterparty === offer.counterparty &&
                     b.utxo.txid === offer.fidelity_bond_data.utxo_txid
            )?.amount || 0;
            bondValue = bondAmount > 0 ? '0' : 'Pending';
        } else {
            bondValue = 'No';
        }

        const directoryBadges = offer.directory_nodes.map(node => {
            const abbr = getDirectoryAbbreviation(node);
            const color = getDirectoryColor(node);
            return `<span class="dir-badge" style="background-color: ${color}" title="${node}">${abbr}</span>`;
        }).join('');

        row.innerHTML = `
            <td class="${typeClass}">${OFFER_TYPE_NAMES[offer.ordertype]}</td>
            <td class="counterparty">${offer.counterparty}</td>
            <td>${offer.oid}</td>
            <td class="${feeClass}">${formatFee(offer)}</td>
            <td>${formatNumber(offer.minsize)}</td>
            <td>${formatNumber(offer.maxsize)}</td>
            <td class="${hasBond}">${bondValue}</td>
            <td class="directory-badges">${directoryBadges}</td>
        `;

        if (offer.fidelity_bond_data) {
            const bondCell = row.querySelector('.bond-value-clickable');
            const bondAmount = orderbookData.fidelitybonds.find(
                b => b.counterparty === offer.counterparty &&
                     b.utxo.txid === offer.fidelity_bond_data.utxo_txid
            )?.amount || 0;
            bondCell.addEventListener('click', () => showBondModal(offer.fidelity_bond_data, bondAmount));
        }

        fragment.appendChild(row);
    });

    tbody.innerHTML = '';
    tbody.appendChild(fragment);

    updateSortIndicators();
}

function updateSortIndicators() {
    document.querySelectorAll('th.sortable').forEach(th => {
        th.classList.remove('asc', 'desc');

        if (th.dataset.sort === sortColumn) {
            th.classList.add(sortDirection);
        }
    });
}

function setupEventListeners() {
    document.querySelectorAll('th.sortable').forEach(th => {
        th.addEventListener('click', () => {
            const column = th.dataset.sort;

            if (sortColumn === column) {
                sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                sortColumn = column;
                sortDirection = 'desc';
            }

            renderTable();
        });
    });

    document.getElementById('filter-directory').addEventListener('change', renderTable);
    document.getElementById('search-counterparty').addEventListener('input', renderTable);

    const closeModal = document.querySelector('.close-modal');
    if (closeModal) {
        closeModal.addEventListener('click', () => {
            document.getElementById('bond-modal').style.display = 'none';
        });
    }

    window.addEventListener('click', (event) => {
        const modal = document.getElementById('bond-modal');
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });
}

setupEventListeners();
fetchOrderbook();
