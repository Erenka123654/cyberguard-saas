const pages=[...document.querySelectorAll(".page")];
const nav=[...document.querySelectorAll("nav a")];
const title=document.getElementById("title");
function showPage(id){pages.forEach(p=>p.classList.toggle("hidden",p.id!==id));nav.forEach(n=>n.classList.toggle("active",n.dataset.page===id));title.textContent=id[0].toUpperCase()+id.slice(1);window.scrollTo(0,0)}
nav.forEach(n=>n.onclick=()=>showPage(n.dataset.page));
document.querySelectorAll("[data-go]").forEach(x=>x.onclick=()=>showPage(x.dataset.go));
const modal=document.getElementById("modal");
document.querySelectorAll(".newscan").forEach(x=>x.onclick=()=>modal.classList.remove("hidden"));
document.querySelector(".close").onclick=()=>modal.classList.add("hidden");
modal.onclick=e=>{if(e.target===modal)modal.classList.add("hidden")};
document.querySelector(".mobile-menu").onclick=()=>document.querySelector(".sidebar").classList.toggle("open");
document.getElementById("start").onclick=()=>{
 const d=document.getElementById("domain").value.trim(), a=document.getElementById("authorized").checked;
 document.getElementById("status").textContent=!d||!a?"Domain ve yetki onayı gereklidir.":"Scan queued. Connect to /api/scans for live execution.";
};
