package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

var _ = a.Resource("search", func() {
	a.BasePath("/search")

	a.Action("users", func() {
		a.Routing(
			a.GET("users"),
		)
		a.Description("Search by fullname")
		a.Params(func() {
			a.Param("q", d.String)
			a.Param("page[offset]", d.String, "Paging start position") // #428
			a.Param("page[limit]", d.Integer, "Paging size")
			a.Required("q")
		})
		a.Response(d.OK, func() {
			a.Media(userList)
		})

		a.Response(d.BadRequest, func() {
			a.Media(d.ErrorMedia)
		})

		a.Response(d.InternalServerError)
	})
})
