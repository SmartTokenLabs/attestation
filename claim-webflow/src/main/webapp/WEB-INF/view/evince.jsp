<html>
<body>
  <h2>Identity Claim</h2>
  
 <form method="post" action="${flowExecutionUrl}">
   <p>Thank you for submitting your identity information.</p>
   <p>Please upload a piece of evince to support the identity information you just submitted.</p>
   <p>
     <input type="file" name="evidence"/>
   </p>
   <p>
    <input type="hidden" name="_eventId" value="provide"/>
    <input type="submit" value="Confirm" />
   </p>
 </form>

<form method="post" action="${flowExecutionUrl}">

    <input type="hidden" name="_eventId" value="cancel">
    <input type="submit" value="Cancel" />

</form>

</body>
</html>
