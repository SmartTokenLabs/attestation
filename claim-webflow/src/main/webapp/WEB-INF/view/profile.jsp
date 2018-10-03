<html>
<body>
  <h2>Identity Claim</h2>
  
 <form method="post" action="${flowExecutionUrl}">
   <p>Please provide your basic identity information.</p>
   <p>All fields are mandantory.</p>
   <table>
     <caption>Identity Information</caption>
     <tbody>
       <tr>
         <th>Given Name</th>
         <td><input name="givenName"/></td>
       </tr>
       <tr>
	 <th>Surname</th>
	 <td><input name="surname"/></td>
       </tr>
       <tr>
	 <th>Full Name</th>
	 <td><input name="commonName"/></td>
       </tr>
       <tr>
	 <th>Birth Date</th>
	 <td><input name="birthDate" type="date"/></td>
       </tr>
      </tbody>
   </table>
   <p>
    <input type="hidden" name="_eventId" value="claim">
    <input type="submit" value="Claim" />
   </p>
 </form>

<form method="post" action="${flowExecutionUrl}">

    <input type="hidden" name="_eventId" value="cancel">
    <input type="submit" value="Cancel" />

</form>

</body>
</html>
