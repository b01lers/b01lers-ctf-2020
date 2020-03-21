function get_life(query) {
  $.ajax({
    type: "GET",
    url: "/query?search=" + query,
    data: "{}",
    contentType: "application/json; charset=utf-8",
    dataType: "json",
    cache: false,
    success: function(data) {
      var table_html =
        '<table id="results"><tr><th>Name</th><th>Description</th></tr>';
      $.each(data, function(i, item) {
        table_html +=
          "<tr><td>" + data[i][0] + "</td><td>" + data[i][1] + "</td></tr>";
      });
      table_html += "</table>";

      $("#results").replaceWith(table_html);
    },

    error: function(msg) { }
  });
}
