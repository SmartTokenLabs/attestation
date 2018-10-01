<html>
<body>
  <h2>Identity Claim</h2>
  <p>In the following a few minutes we will ask you to provide:</p>
  <ul>
    <li>Identity information including nationality, name and date of birth.</li>
    <li>A photo copy of the document proof of these information.</li>
  </ul>
  <p>By continuing, you agree to the following privacy policy:</p>
  <div id="policy" style="overflow: scroll; max-width: 80ex; background: lightgray;">
    <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
  </div>

<%--<a href="${flowExecutionUrl}">Start</a>--%>
<%--<input type="submit" name="_eventId_success" value="Proceed" />--%>
<%--<input type="submit" name="_eventId_failure" value="Cancel" />--%>

<form method="post" action="${flowExecutionUrl}">

    <input type="hidden" name="_eventId" value="agree">
    <input type="submit" value="Proceed" />

</form>

<form method="post" action="${flowExecutionUrl}">

    <input type="hidden" name="_eventId" value="cancel">
    <input type="submit" value="Cancel" />

</form>

</body>
</html>
