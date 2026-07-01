from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def generate_report(result, filename="report.pdf"):
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter

    y = height - 50

    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "TracePort Security Scan Report")

    y -= 40
    c.setFont("Helvetica", 10)

    c.drawString(50, y, f"Target: {result.target}")
    y -= 20
    c.drawString(50, y, f"IP Address: {result.ip_address}")
    y -= 20
    c.drawString(50, y, f"Open Ports: {result.open_ports_count}")
    y -= 20
    c.drawString(50, y, f"Scan Duration: {result.scan_duration:.2f}s")

    y -= 40
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Open Ports & Risk Levels")

    y -= 20
    c.setFont("Helvetica", 10)

    for service in result.services:
        text = f"Port {service.port} | {service.service_name} | {getattr(service, 'risk', 'UNKNOWN')}"
        c.drawString(50, y, text)
        y -= 15

        if y < 50:
            c.showPage()
            y = height - 50

    c.save()
