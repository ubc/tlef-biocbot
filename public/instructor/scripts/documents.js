document.addEventListener('DOMContentLoaded', () => {
    const uploadDropArea = document.getElementById('upload-drop-area');
    const fileUpload = document.getElementById('file-upload');
    const documentSearch = document.getElementById('document-search');
    const documentFilter = document.getElementById('document-filter');
    
    // Handle drag and drop functionality
    if (uploadDropArea) {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            uploadDropArea.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        ['dragenter', 'dragover'].forEach(eventName => {
            uploadDropArea.addEventListener(eventName, highlight, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            uploadDropArea.addEventListener(eventName, unhighlight, false);
        });

        function highlight() {
            uploadDropArea.classList.add('highlight');
        }

        function unhighlight() {
            uploadDropArea.classList.remove('highlight');
        }

        uploadDropArea.addEventListener('drop', handleDrop, false);

        function handleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;
            handleFiles(files);
        }

        uploadDropArea.addEventListener('click', () => {
            fileUpload.click();
        });

        fileUpload.addEventListener('change', (e) => {
            handleFiles(e.target.files);
        });

        function handleFiles(files) {
            // This is just a UI skeleton, so we'll just log the files
            console.log('Files selected:', files);
            // In a real implementation, you would upload these files to the server
            
            // Show a mock upload in progress for demonstration
            Array.from(files).forEach(file => {
                addDocumentRow({
                    name: file.name,
                    type: file.name.split('.').pop().toUpperCase(),
                    size: formatFileSize(file.size),
                    date: new Date().toISOString().split('T')[0],
                    status: 'processing'
                });
            });
        }
    }

    // Search functionality
    if (documentSearch) {
        documentSearch.addEventListener('input', filterDocuments);
    }

    // Filter functionality
    if (documentFilter) {
        documentFilter.addEventListener('change', filterDocuments);
    }

    function filterDocuments() {
        const searchTerm = documentSearch.value.toLowerCase();
        const filterType = documentFilter.value;
        
        const rows = document.querySelectorAll('.documents-table tbody tr');
        
        rows.forEach(row => {
            const name = row.querySelector('td:first-child').textContent.toLowerCase();
            const type = row.querySelector('td:nth-child(2)').textContent.toLowerCase();
            
            const nameMatch = name.includes(searchTerm);
            const typeMatch = filterType === 'all' || type.toLowerCase() === filterType.toLowerCase();
            
            row.style.display = nameMatch && typeMatch ? '' : 'none';
        });
    }

    // Add document to table (for UI demo)
    function addDocumentRow(document) {
        const tbody = document.querySelector('.documents-table tbody');
        if (!tbody) return;
        
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${document.name}</td>
            <td>${document.type}</td>
            <td>${document.size}</td>
            <td>${document.date}</td>
            <td><span class="status ${document.status}">${capitalizeFirstLetter(document.status)}</span></td>
            <td>
                <button class="action-button view">View</button>
                <button class="action-button delete">Delete</button>
            </td>
        `;
        
        // Add event listeners for the buttons
        const viewButton = tr.querySelector('.view');
        const deleteButton = tr.querySelector('.delete');
        
        viewButton.addEventListener('click', () => {
            console.log('View document:', document.name);
            // In a real implementation, this would open the document
        });
        
        deleteButton.addEventListener('click', () => {
            console.log('Delete document:', document.name);
            tr.remove();
            // In a real implementation, this would delete the document from the server
        });
        
        tbody.appendChild(tr);
    }

    // Helper functions
    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }
    
    function capitalizeFirstLetter(string) {
        return string.charAt(0).toUpperCase() + string.slice(1);
    }
}); 