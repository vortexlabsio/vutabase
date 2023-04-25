import { type Password, type User } from '@prisma/client'
import bcrypt from 'bcryptjs'
import { Authenticator } from 'remix-auth'
import { FormStrategy } from 'remix-auth-form'
import invariant from 'tiny-invariant'
import { prisma } from './db.server'
import { sessionStorage } from './session.server'

export type { User }

export const authenticator = new Authenticator<string>(sessionStorage, {
	sessionKey: 'token',
})

authenticator.use(
	new FormStrategy(async ({ form }) => {
		const username = form.get('username')
		const password = form.get('password')

		invariant(typeof username === 'string', 'username must be a string')
		invariant(username.length > 0, 'username must not be empty')

		invariant(typeof password === 'string', 'password must be a string')
		invariant(password.length > 0, 'password must not be empty')

		const user = await verifyLogin(username, password)
		if (!user) {
			throw new Error('Invalid username or password')
		}

		return user.id
	}),
	FormStrategy.name,
)

export async function requireUserId(request: Request) {
	const requestUrl = new URL(request.url)
	const loginParams = new URLSearchParams([
		['redirectTo', `${requestUrl.pathname}${requestUrl.search}`],
	])
	const failureRedirect = `/login?${loginParams}`
	const userId = await authenticator.isAuthenticated(request, {
		failureRedirect,
	})
	return userId
}

export async function getUserId(request: Request) {
	return authenticator.isAuthenticated(request)
}

export async function resetUserPassword({
	email,
	password,
}: {
	email: User['email']
	password: string
}) {
	const hashedPassword = await bcrypt.hash(password, 10)
	return prisma.user.update({
		where: { email },
		data: {
			password: {
				update: {
					hash: hashedPassword,
				},
			},
		},
	})
}

export async function createUser({
	email,
	password,
}: {
	email: User['email']
	password: string
}) {
	const hashedPassword = await getPasswordHash(password)

	return prisma.user.create({
		data: {
			email,
			password: {
				create: {
					hash: hashedPassword,
				},
			},
		},
	})
}

export async function getPasswordHash(password: string) {
	const hash = await bcrypt.hash(password, 10)
	return hash
}

export async function verifyLogin(
	email: User['email'],
	password: Password['hash'],
) {
	const userWithPassword = await prisma.user.findUnique({
		where: { email },
		select: { id: true, password: { select: { hash: true } } },
	})

	if (!userWithPassword || !userWithPassword.password) {
		return null
	}

	const isValid = await bcrypt.compare(password, userWithPassword.password.hash)

	if (!isValid) {
		return null
	}

	return { id: userWithPassword.id }
}