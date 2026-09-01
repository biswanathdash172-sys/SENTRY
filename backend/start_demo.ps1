# start_demo.ps1
# Helper script to launch all 3 required backend processes simultaneously for a demo.

Write-Host "Starting SENTRY Demo Services..." -ForegroundColor Cyan

# Start Uvicorn Backend in the background
Write-Host "1/3 Starting FastAPI Backend on port 8000..."
Start-Process -FilePath "uvicorn" -ArgumentList "main:app --reload --port 8000"

# Wait a brief moment for the backend to bind to port 8000
Start-Sleep -Seconds 2

# Start the Email Poller in the background
Write-Host "2/3 Starting Email Poller..."
Start-Process -FilePath "python" -ArgumentList "services/email_poller.py"

# Start the Notification Poller in the background
Write-Host "3/3 Starting Windows Notification Poller..."
Start-Process -FilePath "python" -ArgumentList "services/notification_poller.py"

Write-Host ""
Write-Host "All processes started in separate windows!" -ForegroundColor Green
Write-Host "Close their respective windows to stop them." -ForegroundColor Yellow
