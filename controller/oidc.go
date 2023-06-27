package controller

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"net/http"
	"one-api/common"
	"one-api/model"
	"strconv"
	"time"
)

var (
	provider *oidc.Provider
)

// OidcClaim is the struct of OIDC claims we need
type OidcClaim struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name,omitempty"`
	Picture       string `json:"picture,omitempty"`
}

func OidcAuth(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get("username")
	if username != nil {
		OIDCBind(c)
		return
	}

	if !common.OidcAuthEnabled {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "管理员未开启通过 OIDC 登录以及注册",
		})
		return
	}
	code := c.Query("code")

	oidcUser, err := getOIDCUserInfoByCode(c, code)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	user := model.User{
		GitHubId: oidcUser.Sub,
	}
	if model.IsGitHubIdAlreadyTaken(user.GitHubId) {
		err := user.FillUserByGitHubId()
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": err.Error(),
			})
			return
		}
	} else {
		if common.RegisterEnabled {
			user.Username = "oidc_" + strconv.Itoa(model.GetMaxUserId()+1)
			if oidcUser.Name != "" {
				user.DisplayName = oidcUser.Name
			} else {
				user.DisplayName = "OIDC User"
			}
			if oidcUser.EmailVerified {
				user.Email = oidcUser.Email
			}
			user.Role = common.RoleCommonUser
			user.Status = common.UserStatusEnabled

			if err := user.Insert(0); err != nil {
				c.JSON(http.StatusOK, gin.H{
					"success": false,
					"message": err.Error(),
				})
				return
			}
		} else {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "管理员关闭了新用户注册",
			})
			return
		}
	}

	if user.Status != common.UserStatusEnabled {
		c.JSON(http.StatusOK, gin.H{
			"message": "用户已被封禁",
			"success": false,
		})
		return
	}
	setupLogin(&user, c)
}

func OIDCBind(c *gin.Context) {
	if !common.OidcAuthEnabled {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "管理员未开启通过 OIDC 登录以及注册",
		})
		return
	}
	code := c.Query("code")
	oidcUser, err := getOIDCUserInfoByCode(c, code)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	user := model.User{
		OidcId: oidcUser.Sub,
	}
	if model.IsOidcIdAlreadyTaken(user.GitHubId) {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "该 OIDC 账户已被绑定",
		})
		return
	}
	session := sessions.Default(c)
	id := session.Get("id")
	// id := c.GetInt("id")  // critical bug!
	user.Id = id.(int)
	err = user.FillUserById()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	user.OidcId = oidcUser.Sub
	err = user.Update(false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "bind",
	})
	return
}

func getOIDCUserInfoByCode(ctx context.Context, code string) (*OidcClaim, error) {
	// set timeout
	ctx, cancel := context.WithTimeout(ctx, common.OidcTimeout)
	defer cancel()
	verifier := provider.Verifier(&oidc.Config{
		ClientID: common.OidcClientId,
	})

	conf := oauth2.Config{
		ClientID:     common.OidcClientId,
		ClientSecret: common.OidcClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  common.ServerAddress + "/oauth/oidc",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	oa2Token, err := conf.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("OIDC exchange error: %w", err)
	}
	rawIdToken, ok := oa2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("OIDC ID token missing: %w", err)
	}

	idToken, err := verifier.Verify(ctx, rawIdToken)
	if err != nil {
		return nil, fmt.Errorf("OIDC verify error: %w", err)
	}

	claim := &OidcClaim{}
	// extract custom claims
	if err := idToken.Claims(claim); err != nil {
		return nil, fmt.Errorf("OIDC claims error: %w", err)
	}
	return claim, nil
}

func InitOidcProvider() {
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	provider, err = oidc.NewProvider(ctx, common.OidcProviderUrl)
	if err != nil {
		panic(fmt.Errorf("OIDC provider init error: %w", err))
	}

	if provider.Endpoint().AuthURL == "" {
		panic("OIDC provider auth url is empty")
	}
	common.OidcAuthUrl = provider.Endpoint().AuthURL
	return
}
