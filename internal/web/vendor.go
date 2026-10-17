package web

// Tucano (github.com/JuniorCarlini/tucano) ships inside the binary, so the
// panel never loads code from a CDN (CSP 'self') and works offline. Updating
// it means copying dist/tucano.min.{css,js} into assets/vendor/tucano and
// changing these hashes; a test fails if the files and the hashes disagree.
const (
	tucanoVersion   = "0.38.0"
	tucanoCSSSHA256 = "5d0f472dd4083904b9c26d27cfa79a439bceda07c3a0aac1b22c7de95c109afa"
	tucanoJSSHA256  = "076ce0d436cbde1b15037937a3aee6bf5b6b3e4e2108c09bdc2145acdfb11f91"
)

// xterm.js (npm @xterm/xterm, with @xterm/addon-fit) draws the service
// terminal. Copied from the npm tarballs (integrity checked) without the
// sourceMappingURL line.
const (
	xtermVersion     = "6.0.0"
	xtermFitVersion  = "0.11.0"
	xtermJSSHA256    = "98d0973151aff2991d335b1adbbdac2e14da26341abe329d677d4c0034402bdf"
	xtermCSSSHA256   = "854a7c0fb70e8b1a083c16797ab827299fb18744f5ad34f227b48337e33293c6"
	xtermFitJSSHA256 = "4df3789fa7bff5d545ba38462a8cd2f7460ba971021bce3f81c2870f937a201e"
)
