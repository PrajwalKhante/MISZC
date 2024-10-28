.catch(error => {
    document.getElementById('loading').style.display = 'none';
    if (error.message.includes('Invalid or inactive domain')) {
        alert('The domain is invalid or inactive. Please check the URL and try again.');
    } else {
        alert('Failed to fetch data. Please try again.');
    }
});
