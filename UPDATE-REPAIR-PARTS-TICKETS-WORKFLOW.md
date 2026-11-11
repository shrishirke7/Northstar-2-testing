# Northstar IT - Repair Workflow, Parts Groups & Ticketing Update

This update contains improvements across the Repair Workflow, Parts Inventory, IT Help Desk & Public Ticketing Portal.

## Summary of Changes

### 1. Attachment / Photo Preview Modal & Download
- Fixed modal layout: now properly centered on the screen as a responsive lightbox overlay with dark blur backdrop instead of appearing cut-off at the bottom-left.
- Fixed the `Close` button and added backdrop click / `Escape` key handlers to close preview reliably.
- Added a `Download` button right next to the `Close` button in the preview header so users can directly download any invoice/ticket attachment.

### 2. Maintenance & Repairs Page Cleanup
- Removed the redundant `+ Log maintenance` button from the top header since maintenance is managed through the 3-stage **Repair workflow** (`+ New repair case`).

### 3. Repair Case Deletion with Auto Stock Reversal & Expense Rollback
- Added a `🗑 Delete` button to each row in the **Repair workflow** table.
- When deleting a repair case:
  - Consumed parts (`partLines`) are automatically restored back into inventory (`newQty`, `repairedQty`, `refurbishedQty` in `partsInventory`).
  - Related part assignments (`partsAssignments`) are cleaned up.
  - Repair expenses (part costs, labor costs, other charges) are automatically deducted/removed from expenses, valuation ledger, and overview KPIs.
  - If linked to a ticket, unlinks cleanly.

### 4. Component Groups & Summary Tiles in Parts Inventory
- Added **Group Category** functionality in the Product/Part Catalog form with autocomplete suggestions (e.g. `RAM`, `Monitors`, `Keyboard & Mouse`, `SSD & Storage`, `SMPS & Power`, `Network & Cables`, `Printers & Supplies`, etc.) and a `+ New group` creation prompt.
- Added an interactive **Component Groups & Categories** summary tiles section positioned between the Product Catalog and the Stock by Factory table:
  - Each tile displays the Group name, icon, available in-stock quantity, number of models, and total value.
  - Clicking any group tile opens a detailed popup modal showing every part in that group, condition breakdown (New, Repaired, Refurbished, Damaged), unit cost, and total value.
  - Includes a direct "View in stock table" button.
- Added a **Group Filter** (`#partsGroupFilter`) in the Stock table toolbar, plus a Group badge tag in the stock table under Category.

### 5. Ticket to Repair Case Integration
- Added a `🔨 Create repair case` button directly in the IT Help Desk ticket queue.
- Clicking it switches to the Maintenance module and pre-fills the Repair Case form with the ticket's Asset, Factory, Department, User, Issue description, and Ticket ID.
- Displays a `🔨 Case: RC-XXXXXX (Stage)` badge on the ticket once linked.

### 6. Multiple Image Attachments in Ticketing Tool
- Fixed the bug where selecting a second image replaced the first.
- The attachment picker now queues up to 5 screenshots/images with chip previews and individual `✕` remove buttons.
- All queued images are attached and uploaded on ticket submit.

### 7. Category Click Glitch Fixed & Comprehensive Categories
- Fixed the click event glitch on radio categories so clicking "Network / Hardware" immediately updates the subcategories list.
- Comprehensive hardware subcategories: Desktop PC, Laptop, Monitor / Screen, Network Switch / Router, Wi-Fi / AP, LAN Cable, Printer / Scanner, CCTV / Surveillance, Server / Storage, UPS / Power, Other Hardware.
- Comprehensive software subcategories: ERP Software, Manufacturing System, Digital Catalog, Reports / Billing, OS / Windows, Email / Login / Outlook, Software License, Other Software.
- Comprehensive material subcategories: RAM, SSD / Hard Drive, Monitor / Screen, Keyboard & Mouse, SMPS / Power Supply, Laptop / Desktop, Network Switch / Cables, Printer / Toner, Accessories / Peripherals, Other Material.

### 8. Structured Material Request & Stock Issuance Workflow
- When "IT material request" is chosen, displays dedicated structured fields: Factory, Department, Employee name, Requested Component, Quantity needed, and Justification.
- Added an `📦 Issue from parts` button on Material Request tickets:
  - Opens stock issuance dialog showing available inventory from that factory.
  - Selects condition (New, Repaired, Refurbished).
  - Automatically deducts stock from `partsInventory` and records assignment under that user's name and department.
  - Automatically marks the ticket as `Resolved` with full issue notes and timestamps.

### 9. Public & Internal Live Queue with Repair Stage & Delivery ETA
- Both internal Help Desk and `portal.html` public view display all tickets (Live, Open, In progress, Resolved, Closed).
- Shows assigned IT technician, current ticket status, linked repair case stage (Stage 1 Intake, Stage 2 Work & parts, Stage 3 Completed/Ready for pickup), and expected delivery date / ETA.

---

## Deployment to Ubuntu Server

1. Transfer `index.html`, `server.py`, and `portal.html` (or extract `Repair-Workflow-Parts-Group-Tickets-Update.zip`) to `/opt/northstar-it`.

2. On the server, back up the previous files:
```bash
cd /opt/northstar-it
sudo cp index.html "index.html.bak.$(date +%Y%m%d-%H%M%S)"
sudo cp server.py "server.py.bak.$(date +%Y%m%d-%H%M%S)"
sudo cp portal.html "portal.html.bak.$(date +%Y%m%d-%H%M%S)"
```

3. Copy the updated files into `/opt/northstar-it`:
```bash
sudo cp index.html /opt/northstar-it/
sudo cp server.py /opt/northstar-it/
sudo cp portal.html /opt/northstar-it/
```

4. Rebuild and restart the container:
```bash
cd /opt/northstar-it
sudo docker compose up -d --build app
sudo docker compose logs --tail=60 app
```

5. Hard-refresh the browser (`Ctrl+Shift+R` or `Ctrl+F5`).
