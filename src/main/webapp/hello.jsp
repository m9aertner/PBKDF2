<%@ page language="java" %>
<jsp:include page="WEB-INF/jspx/header.jsp" />

<p>
Hello, <b><%= request.getRemoteUser() %></b>.
</p>
<p>
<a href="index.jsp">Back</a>
</p>

<jsp:include page="WEB-INF/jspx/footer.jsp" />
