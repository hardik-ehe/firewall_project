import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages

with PdfPages('project-report.pdf') as pdf:
    fig = plt.figure(figsize=(8.27,11.69))
    plt.axis('off')
    plt.text(0.5,0.7,"Packet Filtering & Monitoring Firewall",ha='center',fontsize=18,weight='bold')
    plt.text(0.5,0.6,"Python + NFQUEUE + Scapy",ha='center',fontsize=12)
    pdf.savefig(fig)
    plt.close(fig)
print("Saved project-report.pdf")
