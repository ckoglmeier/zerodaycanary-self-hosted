import {reportBrowserError} from './lib/monitoring/client';
window.addEventListener('error',()=>reportBrowserError());
window.addEventListener('unhandledrejection',()=>reportBrowserError());
