/**
 * Main Entry Point for CONDUIT Dashboard
 *
 * This file bootstraps the React application and renders the root App component.
 * Uses React 19's createRoot API for concurrent rendering features.
 */
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'

// Create root and render the App component
// StrictMode enables additional development checks and warnings
createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
