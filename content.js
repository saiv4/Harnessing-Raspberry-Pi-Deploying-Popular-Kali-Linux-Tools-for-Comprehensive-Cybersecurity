// content.js
(function () {
    console.log("Script Scanner: Scanning page...");

    // Find all script elements
    const scripts = document.querySelectorAll('script');
    const results = Array.from(scripts).map((script) => {
        return script.src
            ? `External Script: ${script.src}`
            : 'Inline Script Detected';
    });

    // Return the results for the popup
    return results;
})();