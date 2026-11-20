
// KURD CYBER PRO

// Dark / Light Mode
function toggleTheme(){
 document.body.classList.toggle("light");

 const mode = document.body.classList.contains("light")
  ? "light"
  : "dark";

 localStorage.setItem("kurd-cyber-theme", mode);
}

// بارکردنی ڕەنگی پێشوو
if(localStorage.getItem("kurd-cyber-theme")==="light"){
 document.body.classList.add("light");
}

// Copy Terminal Commands
function copyCommand(command){
 if(navigator.clipboard && window.isSecureContext){
  navigator.clipboard.writeText(command)
   .then(()=>alert("فەرمانەکە کۆپی کرا!"))
   .catch(()=>alert("تکایە فەرمانەکە بە دەستی کۆپی بکە."));
 }else{
  const area=document.createElement("textarea");
  area.value=command;
  document.body.appendChild(area);
  area.select();
  document.execCommand("copy");
  area.remove();
  alert("فەرمانەکە کۆپی کرا!");
 }
}

// کاتی ئێستا
function updateClock(){
 const now=new Date();
 const clock=document.getElementById("clock");
 if(clock){
  clock.textContent=now.toLocaleTimeString("en-GB");
 }
}

updateClock();
setInterval(updateClock,1000);

console.log("KURD CYBER PRO Loaded Successfully");

