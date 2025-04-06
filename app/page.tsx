"use client"

import { useState, useEffect } from "react"
import {
  PlusCircle,
  Trash2,
  Check,
  X,
  Upload,
  User,
  Key,
  UserPlus,
  ChevronDown,
  ChevronUp,
  Database,
  Hash,
  Globe,
  Home,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"

type UserType = "domain-admin" | "domain-user" | "local-admin" | "local-user" | "service-account" | "unknown"
type PasswordType = "plaintext" | "ntlm" | "unknown"

interface Credential {
  id: string
  username: string
  password: string
  isValid: boolean
  notes: string
  userType: UserType
  passwordType: PasswordType
}

interface Username {
  name: string
  type: UserType
}

interface Password {
  value: string
  type: PasswordType
}

interface Target {
  id: string
  ip: string
  localFlag: string
  proofFlag: string
  credentials: Credential[]
  usernames: Username[]
  passwords: Password[]
  isExpanded: boolean
}

interface BulkAddResult {
  added: string[]
  skipped: string[]
  invalid: string[]
}

export default function OSCPTracker() {
  const [targets, setTargets] = useState<Target[]>([])
  const [newIP, setNewIP] = useState("")
  const [bulkIPs, setBulkIPs] = useState("")
  const [error, setError] = useState("")
  const [bulkAddResult, setBulkAddResult] = useState<BulkAddResult | null>(null)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [credentialDialogOpen, setCredentialDialogOpen] = useState(false)
  const [currentTargetId, setCurrentTargetId] = useState<string | null>(null)
  const [newCredential, setNewCredential] = useState<{
    username: string
    password: string
    notes: string
    userType: UserType
    passwordType: PasswordType
  }>({
    username: "",
    password: "",
    notes: "",
    userType: "unknown",
    passwordType: "plaintext",
  })
  const [showSummary, setShowSummary] = useState(true)
  const [inputState, setInputState] = useState<{
    [targetId: string]: {
      username: string
      userType: UserType
      password: string
      passwordType: PasswordType
    }
  }>({})

  // Load saved targets from localStorage on component mount
  useEffect(() => {
    const savedTargets = localStorage.getItem("oscp-targets")
    if (savedTargets) {
      try {
        const parsed = JSON.parse(savedTargets)
        // Add new properties if they don't exist (for backward compatibility)
        const updatedTargets = parsed.map((target: any) => ({
          ...target,
          credentials: (target.credentials || []).map((cred: any) => ({
            ...cred,
            userType:
              cred.userType === "domain"
                ? "domain-user"
                : cred.userType === "local"
                  ? "local-user"
                  : cred.userType || "unknown",
            passwordType: cred.passwordType || "plaintext",
          })),
          usernames: Array.isArray(target.usernames)
            ? target.usernames.map((u: any) => {
                if (typeof u === "string") {
                  return { name: u, type: "unknown" }
                }
                // Convert old types to new types
                if (u.type === "domain") {
                  return { ...u, type: "domain-user" }
                }
                if (u.type === "local") {
                  return { ...u, type: "local-user" }
                }
                return u
              })
            : [],
          passwords: Array.isArray(target.passwords)
            ? target.passwords.map((p: any) => (typeof p === "string" ? { value: p, type: "plaintext" } : p))
            : [],
          isExpanded: target.isExpanded || false,
        }))
        setTargets(updatedTargets)
      } catch (e) {
        console.error("Error parsing saved targets:", e)
        setTargets([])
      }
    }
  }, [])

  // Save targets to localStorage whenever they change
  useEffect(() => {
    localStorage.setItem("oscp-targets", JSON.stringify(targets))
  }, [targets])

  // Detect if a string is likely an NTLM hash
  const isLikelyNTLM = (str: string): boolean => {
    // NTLM hashes are typically 32 hex characters
    const ntlmRegex = /^[a-fA-F0-9]{32}$/
    return ntlmRegex.test(str)
  }

  // Get all unique usernames across all targets
  const getAllUsernames = () => {
    const allUsernames: { name: string; type: UserType }[] = []
    const seen = new Set<string>()

    targets.forEach((target) => {
      target.usernames.forEach((username) => {
        if (!seen.has(username.name)) {
          seen.add(username.name)
          allUsernames.push(username)
        }
      })

      target.credentials.forEach((cred) => {
        if (!seen.has(cred.username)) {
          seen.add(cred.username)
          allUsernames.push({ name: cred.username, type: cred.userType })
        }
      })
    })

    return allUsernames.sort((a, b) => a.name.localeCompare(b.name))
  }

  // Get all unique passwords across all targets
  const getAllPasswords = () => {
    const allPasswords: { value: string; type: PasswordType }[] = []
    const seen = new Set<string>()

    targets.forEach((target) => {
      target.passwords.forEach((password) => {
        if (!seen.has(password.value)) {
          seen.add(password.value)
          allPasswords.push(password)
        }
      })

      target.credentials.forEach((cred) => {
        if (!seen.has(cred.password)) {
          seen.add(cred.password)
          allPasswords.push({ value: cred.password, type: cred.passwordType })
        }
      })
    })

    return allPasswords.sort((a, b) => a.value.localeCompare(b.value))
  }

  // Get all unique valid credentials across all targets
  const getAllValidCredentials = () => {
    const allValidCredentials: {
      pair: string
      username: string
      password: string
      userType: UserType
      passwordType: PasswordType
    }[] = []
    const seen = new Set<string>()

    targets.forEach((target) => {
      target.credentials.forEach((cred) => {
        if (cred.isValid) {
          const pairKey = `${cred.username}:${cred.password}`
          if (!seen.has(pairKey)) {
            seen.add(pairKey)
            allValidCredentials.push({
              pair: pairKey,
              username: cred.username,
              password: cred.password,
              userType: cred.userType,
              passwordType: cred.passwordType,
            })
          }
        }
      })
    })

    return allValidCredentials.sort((a, b) => a.pair.localeCompare(b.pair))
  }

  const validateIP = (ip: string) => {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
    return ipRegex.test(ip.trim())
  }

  const addTarget = () => {
    if (!validateIP(newIP)) {
      setError("Please enter a valid IP address")
      return
    }

    if (targets.some((target) => target.ip === newIP)) {
      setError("This IP address is already in your list")
      return
    }

    setTargets([
      ...targets,
      {
        id: crypto.randomUUID(),
        ip: newIP,
        localFlag: "",
        proofFlag: "",
        credentials: [],
        usernames: [],
        passwords: [],
        isExpanded: false,
      },
    ])

    setNewIP("")
    setError("")
  }

  const addBulkTargets = () => {
    // Split the input by newlines and filter out empty lines
    const ipLines = bulkIPs
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0)

    const result: BulkAddResult = {
      added: [],
      skipped: [],
      invalid: [],
    }

    const newTargets: Target[] = []

    ipLines.forEach((ip) => {
      if (!validateIP(ip)) {
        result.invalid.push(ip)
        return
      }

      if (targets.some((target) => target.ip === ip)) {
        result.skipped.push(ip)
        return
      }

      newTargets.push({
        id: crypto.randomUUID(),
        ip: ip,
        localFlag: "",
        proofFlag: "",
        credentials: [],
        usernames: [],
        passwords: [],
        isExpanded: false,
      })

      result.added.push(ip)
    })

    if (newTargets.length > 0) {
      setTargets([...targets, ...newTargets])
    }

    setBulkAddResult(result)
    setBulkIPs("")
  }

  const updateFlag = (id: string, flagType: "localFlag" | "proofFlag", value: string) => {
    setTargets(targets.map((target) => (target.id === id ? { ...target, [flagType]: value } : target)))
  }

  const removeTarget = (id: string) => {
    setTargets(targets.filter((target) => target.id !== id))
  }

  const getStatus = (target: Target) => {
    if (target.localFlag && target.proofFlag) return "complete"
    if (target.localFlag || target.proofFlag) return "partial"
    return "pending"
  }

  const toggleExpand = (id: string) => {
    setTargets(targets.map((target) => (target.id === id ? { ...target, isExpanded: !target.isExpanded } : target)))
  }

  const addUsername = (targetId: string) => {
    const targetInput = inputState[targetId] || {
      username: "",
      userType: "unknown",
      password: "",
      passwordType: "plaintext",
    }

    if (!targetInput.username.trim()) return

    setTargets(
      targets.map((target) => {
        if (target.id === targetId) {
          // Only add if it doesn't already exist
          if (!target.usernames.some((u) => u.name === targetInput.username)) {
            return {
              ...target,
              usernames: [...target.usernames, { name: targetInput.username, type: targetInput.userType }],
            }
          }
        }
        return target
      }),
    )

    // Clear just this target's username input
    setInputState({
      ...inputState,
      [targetId]: {
        ...targetInput,
        username: "",
      },
    })
  }

  const addPassword = (targetId: string) => {
    const targetInput = inputState[targetId] || {
      username: "",
      userType: "unknown",
      password: "",
      passwordType: "plaintext",
    }

    if (!targetInput.password.trim()) return

    // Auto-detect if it's likely an NTLM hash
    const detectedType = isLikelyNTLM(targetInput.password) ? "ntlm" : targetInput.passwordType

    setTargets(
      targets.map((target) => {
        if (target.id === targetId) {
          // Only add if it doesn't already exist
          if (!target.passwords.some((p) => p.value === targetInput.password)) {
            return {
              ...target,
              passwords: [...target.passwords, { value: targetInput.password, type: detectedType }],
            }
          }
        }
        return target
      }),
    )

    // Clear just this target's password input
    setInputState({
      ...inputState,
      [targetId]: {
        ...targetInput,
        password: "",
      },
    })
  }

  const removeUsername = (targetId: string, username: string) => {
    setTargets(
      targets.map((target) => {
        if (target.id === targetId) {
          return {
            ...target,
            usernames: target.usernames.filter((u) => u.name !== username),
          }
        }
        return target
      }),
    )
  }

  const removePassword = (targetId: string, password: string) => {
    setTargets(
      targets.map((target) => {
        if (target.id === targetId) {
          return {
            ...target,
            passwords: target.passwords.filter((p) => p.value !== password),
          }
        }
        return target
      }),
    )
  }

  const updateUsernameType = (targetId: string, username: string, type: UserType) => {
    setTargets(
      targets.map((target) => {
        if (target.id === targetId) {
          return {
            ...target,
            usernames: target.usernames.map((u) => (u.name === username ? { ...u, type } : u)),
          }
        }
        return target
      }),
    )
  }

  const updatePasswordType = (targetId: string, password: string, type: PasswordType) => {
    setTargets(
      targets.map((target) => {
        if (target.id === targetId) {
          return {
            ...target,
            passwords: target.passwords.map((p) => (p.value === password ? { ...p, type } : p)),
          }
        }
        return target
      }),
    )
  }

  const addCredential = (targetId: string) => {
    if (!newCredential.username.trim() || !newCredential.password.trim()) return

    // Auto-detect if it's likely an NTLM hash
    const detectedPasswordType = isLikelyNTLM(newCredential.password) ? "ntlm" : newCredential.passwordType

    setTargets(
      targets.map((target) => {
        if (target.id === targetId) {
          return {
            ...target,
            credentials: [
              ...target.credentials,
              {
                id: crypto.randomUUID(),
                username: newCredential.username,
                password: newCredential.password,
                isValid: true,
                notes: newCredential.notes,
                userType: newCredential.userType,
                passwordType: detectedPasswordType,
              },
            ],
          }
        }
        return target
      }),
    )

    setNewCredential({
      username: "",
      password: "",
      notes: "",
      userType: "unknown",
      passwordType: "plaintext",
    })
    setCredentialDialogOpen(false)
  }

  const removeCredential = (targetId: string, credentialId: string) => {
    setTargets(
      targets.map((target) => {
        if (target.id === targetId) {
          return {
            ...target,
            credentials: target.credentials.filter((cred) => cred.id !== credentialId),
          }
        }
        return target
      }),
    )
  }

  const toggleCredentialValidity = (targetId: string, credentialId: string) => {
    setTargets(
      targets.map((target) => {
        if (target.id === targetId) {
          return {
            ...target,
            credentials: target.credentials.map((cred) => {
              if (cred.id === credentialId) {
                return { ...cred, isValid: !cred.isValid }
              }
              return cred
            }),
          }
        }
        return target
      }),
    )
  }

  const updateCredentialField = (
    targetId: string,
    credentialId: string,
    field: keyof Credential,
    value: string | boolean | UserType | PasswordType,
  ) => {
    setTargets(
      targets.map((target) => {
        if (target.id === targetId) {
          return {
            ...target,
            credentials: target.credentials.map((cred) => {
              if (cred.id === credentialId) {
                return { ...cred, [field]: value }
              }
              return cred
            }),
          }
        }
        return target
      }),
    )
  }

  // Calculate summary statistics
  const totalTargets = targets.length
  const completedTargets = targets.filter((t) => t.localFlag && t.proofFlag).length
  const partialTargets = targets.filter((t) => (t.localFlag || t.proofFlag) && !(t.localFlag && t.proofFlag)).length

  // Get usernames by type category
  const getUsernamesByType = (type: UserType) => {
    return getAllUsernames()
      .filter((u) => u.type === type)
      .map((u) => u.name)
  }

  // Get passwords by type
  const getPasswordsByType = (type: PasswordType) => {
    return getAllPasswords()
      .filter((p) => p.type === type)
      .map((p) => p.value)
  }

  // Get valid credentials by password type
  const getValidCredentialsByPasswordType = (type: PasswordType) => {
    return getAllValidCredentials().filter((c) => c.passwordType === type)
  }

  return (
    <div className="container mx-auto py-8 max-w-6xl">
      <Card className="mb-8">
        <CardHeader>
          <CardTitle className="text-2xl">OSCP Target Tracker</CardTitle>
          <CardDescription>Track your progress on OSCP targets, flags, and credentials</CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="single">
            <TabsList className="mb-4">
              <TabsTrigger value="single">Add Single IP</TabsTrigger>
              <TabsTrigger value="bulk">Add Multiple IPs</TabsTrigger>
            </TabsList>

            <TabsContent value="single">
              <div className="flex gap-4 mb-2">
                <Input
                  placeholder="Enter IP address (e.g. 10.10.10.10)"
                  value={newIP}
                  onChange={(e) => setNewIP(e.target.value)}
                  className="flex-1"
                />
                <Button onClick={addTarget}>
                  <PlusCircle className="mr-2 h-4 w-4" /> Add Target
                </Button>
              </div>
              {error && <p className="text-sm text-red-500 mt-1">{error}</p>}
            </TabsContent>

            <TabsContent value="bulk">
              <div className="space-y-4">
                <Textarea
                  placeholder="Enter multiple IP addresses (one per line)"
                  value={bulkIPs}
                  onChange={(e) => setBulkIPs(e.target.value)}
                  className="min-h-[150px] font-mono"
                />
                <Button
                  onClick={() => {
                    addBulkTargets()
                    setDialogOpen(true)
                  }}
                >
                  <Upload className="mr-2 h-4 w-4" /> Add Multiple Targets
                </Button>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {targets.length > 0 && (
        <Card className="mb-8">
          <CardHeader className="pb-2">
            <div className="flex justify-between items-center">
              <CardTitle className="flex items-center">
                <Database className="h-5 w-5 mr-2" /> Summary Dashboard
              </CardTitle>
              <Button variant="ghost" size="sm" onClick={() => setShowSummary(!showSummary)}>
                {showSummary ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </Button>
            </div>
            <CardDescription>Overview of all discovered information across targets</CardDescription>
          </CardHeader>

          {showSummary && (
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <div className="bg-muted rounded-lg p-4 text-center">
                  <div className="text-2xl font-bold">{totalTargets}</div>
                  <div className="text-sm text-muted-foreground">Total Targets</div>
                </div>
                <div className="bg-green-100 rounded-lg p-4 text-center">
                  <div className="text-2xl font-bold text-green-700">{completedTargets}</div>
                  <div className="text-sm text-green-700">Completed</div>
                </div>
                <div className="bg-yellow-100 rounded-lg p-4 text-center">
                  <div className="text-2xl font-bold text-yellow-700">{partialTargets}</div>
                  <div className="text-sm text-yellow-700">Partial</div>
                </div>
              </div>

              <Tabs defaultValue="usernames" className="mt-6">
                <TabsList className="mb-4">
                  <TabsTrigger value="usernames">Usernames</TabsTrigger>
                  <TabsTrigger value="passwords">Passwords</TabsTrigger>
                  <TabsTrigger value="credentials">Valid Credentials</TabsTrigger>
                </TabsList>

                <TabsContent value="usernames">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    {/* Domain Users */}
                    <Card className="border-dashed">
                      <CardHeader className="py-3">
                        <CardTitle className="text-sm flex items-center">
                          <Globe className="h-4 w-4 mr-2" /> Domain Users
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="py-0 h-[200px]">
                        <ScrollArea className="h-full pr-4">
                          {getUsernamesByType("domain-user").length > 0 ? (
                            <div className="space-y-1">
                              {getUsernamesByType("domain-user").map((username, index) => (
                                <div key={index} className="font-mono text-sm bg-muted p-1 rounded">
                                  {username}
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p className="text-sm text-muted-foreground">No domain users discovered yet</p>
                          )}
                        </ScrollArea>
                      </CardContent>
                      <CardFooter className="py-2 text-xs text-muted-foreground">
                        Total: {getUsernamesByType("domain-user").length}
                      </CardFooter>
                    </Card>

                    {/* Local Users */}
                    <Card className="border-dashed">
                      <CardHeader className="py-3">
                        <CardTitle className="text-sm flex items-center">
                          <Home className="h-4 w-4 mr-2" /> Local Users
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="py-0 h-[200px]">
                        <ScrollArea className="h-full pr-4">
                          {getUsernamesByType("local-user").length > 0 ? (
                            <div className="space-y-1">
                              {getUsernamesByType("local-user").map((username, index) => (
                                <div key={index} className="font-mono text-sm bg-muted p-1 rounded">
                                  {username}
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p className="text-sm text-muted-foreground">No local users discovered yet</p>
                          )}
                        </ScrollArea>
                      </CardContent>
                      <CardFooter className="py-2 text-xs text-muted-foreground">
                        Total: {getUsernamesByType("local-user").length}
                      </CardFooter>
                    </Card>

                    {/* Service Accounts */}
                    <Card className="border-dashed">
                      <CardHeader className="py-3">
                        <CardTitle className="text-sm flex items-center">
                          <User className="h-4 w-4 mr-2 text-purple-500" /> Service Accounts
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="py-0 h-[200px]">
                        <ScrollArea className="h-full pr-4">
                          {getUsernamesByType("service-account").length > 0 ? (
                            <div className="space-y-1">
                              {getUsernamesByType("service-account").map((username, index) => (
                                <div key={index} className="font-mono text-sm bg-muted p-1 rounded">
                                  {username}
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p className="text-sm text-muted-foreground">No service accounts discovered yet</p>
                          )}
                        </ScrollArea>
                      </CardContent>
                      <CardFooter className="py-2 text-xs text-muted-foreground">
                        Total: {getUsernamesByType("service-account").length}
                      </CardFooter>
                    </Card>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
                    {/* Domain Admin Users */}
                    <Card className="border-dashed">
                      <CardHeader className="py-3">
                        <CardTitle className="text-sm flex items-center">
                          <Globe className="h-4 w-4 mr-2 text-red-500" /> Domain Administrators
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="py-0 h-[200px]">
                        <ScrollArea className="h-full pr-4">
                          {getUsernamesByType("domain-admin").length > 0 ? (
                            <div className="space-y-1">
                              {getUsernamesByType("domain-admin").map((username, index) => (
                                <div key={index} className="font-mono text-sm bg-muted p-1 rounded">
                                  {username}
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p className="text-sm text-muted-foreground">No domain administrators discovered yet</p>
                          )}
                        </ScrollArea>
                      </CardContent>
                      <CardFooter className="py-2 text-xs text-muted-foreground">
                        Total: {getUsernamesByType("domain-admin").length}
                      </CardFooter>
                    </Card>

                    {/* Local Admin Users */}
                    <Card className="border-dashed">
                      <CardHeader className="py-3">
                        <CardTitle className="text-sm flex items-center">
                          <Home className="h-4 w-4 mr-2 text-red-500" /> Local Administrators
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="py-0 h-[200px]">
                        <ScrollArea className="h-full pr-4">
                          {getUsernamesByType("local-admin").length > 0 ? (
                            <div className="space-y-1">
                              {getUsernamesByType("local-admin").map((username, index) => (
                                <div key={index} className="font-mono text-sm bg-muted p-1 rounded">
                                  {username}
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p className="text-sm text-muted-foreground">No local administrators discovered yet</p>
                          )}
                        </ScrollArea>
                      </CardContent>
                      <CardFooter className="py-2 text-xs text-muted-foreground">
                        Total: {getUsernamesByType("local-admin").length}
                      </CardFooter>
                    </Card>
                  </div>
                </TabsContent>

                <TabsContent value="passwords">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* Plaintext Passwords */}
                    <Card className="border-dashed">
                      <CardHeader className="py-3">
                        <CardTitle className="text-sm flex items-center">
                          <Key className="h-4 w-4 mr-2" /> Plaintext Passwords
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="py-0 h-[200px]">
                        <ScrollArea className="h-full pr-4">
                          {getPasswordsByType("plaintext").length > 0 ? (
                            <div className="space-y-1">
                              {getPasswordsByType("plaintext").map((password, index) => (
                                <div key={index} className="font-mono text-sm bg-muted p-1 rounded">
                                  {password}
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p className="text-sm text-muted-foreground">No plaintext passwords discovered yet</p>
                          )}
                        </ScrollArea>
                      </CardContent>
                      <CardFooter className="py-2 text-xs text-muted-foreground">
                        Total: {getPasswordsByType("plaintext").length}
                      </CardFooter>
                    </Card>

                    {/* NTLM Hashes */}
                    <Card className="border-dashed">
                      <CardHeader className="py-3">
                        <CardTitle className="text-sm flex items-center">
                          <Hash className="h-4 w-4 mr-2" /> NTLM Hashes
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="py-0 h-[200px]">
                        <ScrollArea className="h-full pr-4">
                          {getPasswordsByType("ntlm").length > 0 ? (
                            <div className="space-y-1">
                              {getPasswordsByType("ntlm").map((hash, index) => (
                                <div key={index} className="font-mono text-sm bg-muted p-1 rounded">
                                  {hash}
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p className="text-sm text-muted-foreground">No NTLM hashes discovered yet</p>
                          )}
                        </ScrollArea>
                      </CardContent>
                      <CardFooter className="py-2 text-xs text-muted-foreground">
                        Total: {getPasswordsByType("ntlm").length}
                      </CardFooter>
                    </Card>
                  </div>
                </TabsContent>

                <TabsContent value="credentials">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* Plaintext Credentials */}
                    <Card className="border-dashed">
                      <CardHeader className="py-3">
                        <CardTitle className="text-sm flex items-center">
                          <UserPlus className="h-4 w-4 mr-2" /> Plaintext Credentials
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="py-0 h-[200px]">
                        <ScrollArea className="h-full pr-4">
                          {getValidCredentialsByPasswordType("plaintext").length > 0 ? (
                            <div className="space-y-1">
                              {getValidCredentialsByPasswordType("plaintext").map((cred, index) => (
                                <div key={index} className="font-mono text-sm bg-muted p-1 rounded flex items-center">
                                  <span>{cred.pair}</span>
                                  {cred.userType === "domain-admin" && (
                                    <Badge variant="outline" className="ml-2 text-xs">
                                      <Globe className="h-3 w-3 mr-1" /> Domain Admin
                                    </Badge>
                                  )}
                                  {cred.userType === "domain-user" && (
                                    <Badge variant="outline" className="ml-2 text-xs">
                                      <Globe className="h-3 w-3 mr-1" /> Domain User
                                    </Badge>
                                  )}
                                  {cred.userType === "local-admin" && (
                                    <Badge variant="outline" className="ml-2 text-xs">
                                      <Home className="h-3 w-3 mr-1" /> Local Admin
                                    </Badge>
                                  )}
                                  {cred.userType === "local-user" && (
                                    <Badge variant="outline" className="ml-2 text-xs">
                                      <Home className="h-3 w-3 mr-1" /> Local User
                                    </Badge>
                                  )}
                                  {cred.userType === "service-account" && (
                                    <Badge variant="outline" className="ml-2 text-xs">
                                      <User className="h-3 w-3 mr-1" /> Service
                                    </Badge>
                                  )}
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p className="text-sm text-muted-foreground">No plaintext credentials added yet</p>
                          )}
                        </ScrollArea>
                      </CardContent>
                      <CardFooter className="py-2 text-xs text-muted-foreground">
                        Total: {getValidCredentialsByPasswordType("plaintext").length}
                      </CardFooter>
                    </Card>

                    {/* NTLM Credentials */}
                    <Card className="border-dashed">
                      <CardHeader className="py-3">
                        <CardTitle className="text-sm flex items-center">
                          <Hash className="h-4 w-4 mr-2" /> NTLM Credentials
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="py-0 h-[200px]">
                        <ScrollArea className="h-full pr-4">
                          {getValidCredentialsByPasswordType("ntlm").length > 0 ? (
                            <div className="space-y-1">
                              {getValidCredentialsByPasswordType("ntlm").map((cred, index) => (
                                <div key={index} className="font-mono text-sm bg-muted p-1 rounded flex items-center">
                                  <span>{cred.pair}</span>
                                  {cred.userType === "domain-admin" && (
                                    <Badge variant="outline" className="ml-2 text-xs">
                                      <Globe className="h-3 w-3 mr-1" /> Domain Admin
                                    </Badge>
                                  )}
                                  {cred.userType === "domain-user" && (
                                    <Badge variant="outline" className="ml-2 text-xs">
                                      <Globe className="h-3 w-3 mr-1" /> Domain User
                                    </Badge>
                                  )}
                                  {cred.userType === "local-admin" && (
                                    <Badge variant="outline" className="ml-2 text-xs">
                                      <Home className="h-3 w-3 mr-1" /> Local Admin
                                    </Badge>
                                  )}
                                  {cred.userType === "local-user" && (
                                    <Badge variant="outline" className="ml-2 text-xs">
                                      <Home className="h-3 w-3 mr-1" /> Local User
                                    </Badge>
                                  )}
                                  {cred.userType === "service-account" && (
                                    <Badge variant="outline" className="ml-2 text-xs">
                                      <User className="h-3 w-3 mr-1" /> Service
                                    </Badge>
                                  )}
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p className="text-sm text-muted-foreground">No NTLM credentials added yet</p>
                          )}
                        </ScrollArea>
                      </CardContent>
                      <CardFooter className="py-2 text-xs text-muted-foreground">
                        Total: {getValidCredentialsByPasswordType("ntlm").length}
                      </CardFooter>
                    </Card>
                  </div>
                </TabsContent>
              </Tabs>
            </CardContent>
          )}
        </Card>
      )}

      <Dialog open={dialogOpen && bulkAddResult !== null} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Bulk Add Results</DialogTitle>
            <DialogDescription>Summary of IP addresses processed</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 mt-4">
            {bulkAddResult?.added.length ? (
              <div>
                <h4 className="font-medium text-green-600 flex items-center">
                  <Check className="h-4 w-4 mr-2" /> Added ({bulkAddResult.added.length})
                </h4>
                <div className="mt-1 text-sm font-mono bg-muted p-2 rounded max-h-[100px] overflow-y-auto">
                  {bulkAddResult.added.join(", ")}
                </div>
              </div>
            ) : null}

            {bulkAddResult?.skipped.length ? (
              <div>
                <h4 className="font-medium text-yellow-600 flex items-center">
                  <X className="h-4 w-4 mr-2" /> Skipped - Already Exists ({bulkAddResult.skipped.length})
                </h4>
                <div className="mt-1 text-sm font-mono bg-muted p-2 rounded max-h-[100px] overflow-y-auto">
                  {bulkAddResult.skipped.join(", ")}
                </div>
              </div>
            ) : null}

            {bulkAddResult?.invalid.length ? (
              <div>
                <h4 className="font-medium text-red-600 flex items-center">
                  <X className="h-4 w-4 mr-2" /> Invalid IP Format ({bulkAddResult.invalid.length})
                </h4>
                <div className="mt-1 text-sm font-mono bg-muted p-2 rounded max-h-[100px] overflow-y-auto">
                  {bulkAddResult.invalid.join(", ")}
                </div>
              </div>
            ) : null}
          </div>
          <Button onClick={() => setDialogOpen(false)} className="mt-4">
            Close
          </Button>
        </DialogContent>
      </Dialog>

      <Dialog open={credentialDialogOpen} onOpenChange={setCredentialDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Valid Credential</DialogTitle>
            <DialogDescription>Add a working username/password combination</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 mt-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Username</label>
              <Input
                value={newCredential.username}
                onChange={(e) => setNewCredential({ ...newCredential, username: e.target.value })}
                placeholder="Username"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">User Type</label>
              <Select
                value={newCredential.userType}
                onValueChange={(value: UserType) => setNewCredential({ ...newCredential, userType: value })}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select user type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="domain-admin">
                    <div className="flex items-center">
                      <Globe className="h-4 w-4 mr-2 text-red-500" /> Domain Administrator
                    </div>
                  </SelectItem>
                  <SelectItem value="domain-user">
                    <div className="flex items-center">
                      <Globe className="h-4 w-4 mr-2 text-blue-500" /> Domain User
                    </div>
                  </SelectItem>
                  <SelectItem value="local-admin">
                    <div className="flex items-center">
                      <Home className="h-4 w-4 mr-2 text-red-500" /> Local Administrator
                    </div>
                  </SelectItem>
                  <SelectItem value="local-user">
                    <div className="flex items-center">
                      <Home className="h-4 w-4 mr-2 text-green-500" /> Local User
                    </div>
                  </SelectItem>
                  <SelectItem value="service-account">
                    <div className="flex items-center">
                      <User className="h-4 w-4 mr-2 text-purple-500" /> Service Account
                    </div>
                  </SelectItem>
                  <SelectItem value="unknown">
                    <div className="flex items-center">
                      <User className="h-4 w-4 mr-2" /> Unknown
                    </div>
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Password</label>
              <Input
                value={newCredential.password}
                onChange={(e) => setNewCredential({ ...newCredential, password: e.target.value })}
                placeholder="Password"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Password Type</label>
              <Select
                value={newCredential.passwordType}
                onChange={(e) => setNewCredential({ ...newCredential, passwordType: e.target.value })}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select password type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="plaintext">
                    <div className="flex items-center">
                      <Key className="h-4 w-4 mr-2" /> Plaintext
                    </div>
                  </SelectItem>
                  <SelectItem value="ntlm">
                    <div className="flex items-center">
                      <Hash className="h-4 w-4 mr-2" /> NTLM Hash
                    </div>
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Notes (optional)</label>
              <Textarea
                value={newCredential.notes}
                onChange={(e) => setNewCredential({ ...newCredential, notes: e.target.value })}
                placeholder="Service, permissions, etc."
              />
            </div>
          </div>
          <DialogFooter>
            <Button onClick={() => currentTargetId && addCredential(currentTargetId)}>Add Credential</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {targets.length > 0 ? (
        <div className="space-y-6">
          {targets.map((target) => (
            <Card key={target.id}>
              <CardHeader className="pb-2">
                <div className="flex justify-between items-center">
                  <div className="flex items-center gap-2">
                    <CardTitle className="font-mono">{target.ip}</CardTitle>
                    {getStatus(target) === "complete" && (
                      <Badge className="bg-green-500">
                        <Check className="h-3 w-3 mr-1" /> Complete
                      </Badge>
                    )}
                    {getStatus(target) === "partial" && <Badge className="bg-yellow-500">Partial</Badge>}
                    {getStatus(target) === "pending" && (
                      <Badge variant="outline">
                        <X className="h-3 w-3 mr-1" /> Pending
                      </Badge>
                    )}
                  </div>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => removeTarget(target.id)}
                    className="text-red-500 hover:text-red-700"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">local.txt</label>
                    <Input
                      placeholder="Enter local.txt flag"
                      value={target.localFlag}
                      onChange={(e) => updateFlag(target.id, "localFlag", e.target.value)}
                      className="font-mono text-sm"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">proof.txt</label>
                    <Input
                      placeholder="Enter proof.txt flag"
                      value={target.proofFlag}
                      onChange={(e) => updateFlag(target.id, "proofFlag", e.target.value)}
                      className="font-mono text-sm"
                    />
                  </div>
                </div>

                <div className="mt-4">
                  <Button
                    variant="outline"
                    className="w-full flex justify-between items-center"
                    onClick={() => toggleExpand(target.id)}
                  >
                    <span>Credentials & Discovery</span>
                    {target.isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                  </Button>

                  {target.isExpanded && (
                    <div className="mt-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        {/* Discovered Usernames */}
                        <Card className="border-dashed">
                          <CardHeader className="py-3">
                            <CardTitle className="text-sm flex items-center">
                              <User className="h-4 w-4 mr-2" /> Discovered Usernames
                            </CardTitle>
                          </CardHeader>
                          <CardContent className="py-0">
                            <div className="flex flex-wrap gap-2 mb-3">
                              {target.usernames.length > 0 ? (
                                target.usernames.map((username, index) => (
                                  <Badge key={index} variant="secondary" className="flex gap-1 items-center">
                                    {username.name}
                                    {username.type === "domain-admin" && (
                                      <Globe className="h-3 w-3 ml-1 text-red-500" />
                                    )}
                                    {username.type === "domain-user" && (
                                      <Globe className="h-3 w-3 ml-1 text-blue-500" />
                                    )}
                                    {username.type === "local-admin" && <Home className="h-3 w-3 ml-1 text-red-500" />}
                                    {username.type === "local-user" && <Home className="h-3 w-3 ml-1 text-green-500" />}
                                    {username.type === "service-account" && (
                                      <User className="h-3 w-3 ml-1 text-purple-500" />
                                    )}
                                    <Select
                                      value={username.type}
                                      onValueChange={(value: UserType) =>
                                        updateUsernameType(target.id, username.name, value as UserType)
                                      }
                                    >
                                      <SelectTrigger className="h-5 w-5 p-0 ml-1 border-none">
                                        <ChevronDown className="h-3 w-3" />
                                      </SelectTrigger>
                                      <SelectContent>
                                        <SelectItem value="domain-admin">Domain Admin</SelectItem>
                                        <SelectItem value="domain-user">Domain User</SelectItem>
                                        <SelectItem value="local-admin">Local Admin</SelectItem>
                                        <SelectItem value="local-user">Local User</SelectItem>
                                        <SelectItem value="service-account">Service</SelectItem>
                                        <SelectItem value="unknown">Unknown</SelectItem>
                                      </SelectContent>
                                    </Select>
                                    <Button
                                      variant="ghost"
                                      size="icon"
                                      className="h-4 w-4 p-0 ml-1 text-muted-foreground hover:text-foreground"
                                      onClick={() => removeUsername(target.id, username.name)}
                                    >
                                      <X className="h-3 w-3" />
                                    </Button>
                                  </Badge>
                                ))
                              ) : (
                                <p className="text-sm text-muted-foreground">No usernames discovered yet</p>
                              )}
                            </div>
                            <div className="flex gap-2">
                              <Input
                                placeholder="Add username"
                                value={inputState[target.id]?.username || ""}
                                onChange={(e) =>
                                  setInputState({
                                    ...inputState,
                                    [target.id]: {
                                      ...(inputState[target.id] || {
                                        username: "",
                                        userType: "unknown",
                                        password: "",
                                        passwordType: "plaintext",
                                      }),
                                      username: e.target.value,
                                    },
                                  })
                                }
                                className="text-sm"
                                onKeyDown={(e) => e.key === "Enter" && addUsername(target.id)}
                              />
                              <Select
                                value={inputState[target.id]?.userType || "unknown"}
                                onValueChange={(value: UserType) =>
                                  setInputState({
                                    ...inputState,
                                    [target.id]: {
                                      ...(inputState[target.id] || {
                                        username: "",
                                        userType: "unknown",
                                        password: "",
                                        passwordType: "plaintext",
                                      }),
                                      userType: value,
                                    },
                                  })
                                }
                              >
                                <SelectTrigger className="w-[150px]">
                                  <SelectValue placeholder="Type" />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value="domain-admin">Domain Admin</SelectItem>
                                  <SelectItem value="domain-user">Domain User</SelectItem>
                                  <SelectItem value="local-admin">Local Admin</SelectItem>
                                  <SelectItem value="local-user">Local User</SelectItem>
                                  <SelectItem value="service-account">Service Account</SelectItem>
                                  <SelectItem value="unknown">Unknown</SelectItem>
                                </SelectContent>
                              </Select>
                              <Button size="sm" onClick={() => addUsername(target.id)}>
                                Add
                              </Button>
                            </div>
                          </CardContent>
                        </Card>

                        {/* Discovered Passwords */}
                        <Card className="border-dashed">
                          <CardHeader className="py-3">
                            <CardTitle className="text-sm flex items-center">
                              <Key className="h-4 w-4 mr-2" /> Discovered Passwords
                            </CardTitle>
                          </CardHeader>
                          <CardContent className="py-0">
                            <div className="flex flex-wrap gap-2 mb-3">
                              {target.passwords.length > 0 ? (
                                target.passwords.map((password, index) => (
                                  <Badge key={index} variant="secondary" className="flex gap-1 items-center">
                                    {password.value}
                                    {password.type === "ntlm" && <Hash className="h-3 w-3 ml-1 text-purple-500" />}
                                    <Select
                                      value={password.type}
                                      onValueChange={(value: PasswordType) =>
                                        updatePasswordType(target.id, password.value, value as PasswordType)
                                      }
                                    >
                                      <SelectTrigger className="h-5 w-5 p-0 ml-1 border-none">
                                        <ChevronDown className="h-3 w-3" />
                                      </SelectTrigger>
                                      <SelectContent>
                                        <SelectItem value="plaintext">Plaintext</SelectItem>
                                        <SelectItem value="ntlm">NTLM</SelectItem>
                                      </SelectContent>
                                    </Select>
                                    <Button
                                      variant="ghost"
                                      size="icon"
                                      className="h-4 w-4 p-0 ml-1 text-muted-foreground hover:text-foreground"
                                      onClick={() => removePassword(target.id, password.value)}
                                    >
                                      <X className="h-3 w-3" />
                                    </Button>
                                  </Badge>
                                ))
                              ) : (
                                <p className="text-sm text-muted-foreground">No passwords discovered yet</p>
                              )}
                            </div>
                            <div className="flex gap-2">
                              <Input
                                placeholder="Add password"
                                value={inputState[target.id]?.password || ""}
                                onChange={(e) =>
                                  setInputState({
                                    ...inputState,
                                    [target.id]: {
                                      ...(inputState[target.id] || {
                                        username: "",
                                        userType: "unknown",
                                        password: "",
                                        passwordType: "plaintext",
                                      }),
                                      password: e.target.value,
                                    },
                                  })
                                }
                                className="text-sm"
                                onKeyDown={(e) => e.key === "Enter" && addPassword(target.id)}
                              />
                              <Select
                                value={inputState[target.id]?.passwordType || "plaintext"}
                                onValueChange={(value: PasswordType) =>
                                  setInputState({
                                    ...inputState,
                                    [target.id]: {
                                      ...(inputState[target.id] || {
                                        username: "",
                                        userType: "unknown",
                                        password: "",
                                        passwordType: "plaintext",
                                      }),
                                      passwordType: value,
                                    },
                                  })
                                }
                              >
                                <SelectTrigger className="w-[110px]">
                                  <SelectValue placeholder="Type" />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value="plaintext">Plaintext</SelectItem>
                                  <SelectItem value="ntlm">NTLM</SelectItem>
                                </SelectContent>
                              </Select>
                              <Button size="sm" onClick={() => addPassword(target.id)}>
                                Add
                              </Button>
                            </div>
                          </CardContent>
                        </Card>

                        {/* Valid Credentials */}
                        <Card className="md:col-span-2">
                          <CardHeader className="py-3">
                            <div className="flex justify-between items-center">
                              <CardTitle className="text-sm flex items-center">
                                <UserPlus className="h-4 w-4 mr-2" /> Valid Credentials
                              </CardTitle>
                              <Button
                                size="sm"
                                onClick={() => {
                                  setCurrentTargetId(target.id)
                                  setCredentialDialogOpen(true)
                                }}
                              >
                                Add Credential
                              </Button>
                            </div>
                          </CardHeader>
                          <CardContent className="py-0">
                            {target.credentials.length > 0 ? (
                              <Table>
                                <TableHeader>
                                  <TableRow>
                                    <TableHead>Status</TableHead>
                                    <TableHead>Username</TableHead>
                                    <TableHead>Type</TableHead>
                                    <TableHead>Password</TableHead>
                                    <TableHead>Type</TableHead>
                                    <TableHead>Notes</TableHead>
                                    <TableHead className="w-[80px]">Actions</TableHead>
                                  </TableRow>
                                </TableHeader>
                                <TableBody>
                                  {target.credentials.map((cred) => (
                                    <TableRow key={cred.id}>
                                      <TableCell>
                                        <Button
                                          variant="ghost"
                                          size="sm"
                                          className={`p-0 h-6 ${cred.isValid ? "text-green-500" : "text-red-500"}`}
                                          onClick={() => toggleCredentialValidity(target.id, cred.id)}
                                        >
                                          {cred.isValid ? <Check className="h-4 w-4" /> : <X className="h-4 w-4" />}
                                        </Button>
                                      </TableCell>
                                      <TableCell className="font-mono">{cred.username}</TableCell>
                                      <TableCell>
                                        <Select
                                          value={cred.userType}
                                          onValueChange={(value: UserType) =>
                                            updateCredentialField(target.id, cred.id, "userType", value)
                                          }
                                        >
                                          <SelectTrigger className="h-8 w-[130px]">
                                            <SelectValue />
                                          </SelectTrigger>
                                          <SelectContent>
                                            <SelectItem value="local-admin">
                                              <div className="flex items-center">
                                                <Home className="h-4 w-4 mr-2 text-red-500" /> Local Admin
                                              </div>
                                            </SelectItem>
                                            <SelectItem value="local-user">
                                              <div className="flex items-center">
                                                <Home className="h-4 w-4 mr-2 text-green-500" /> Local User
                                              </div>
                                            </SelectItem>
                                            <SelectItem value="domain-admin">
                                              <div className="flex items-center">
                                                <Globe className="h-4 w-4 mr-2 text-red-500" /> Domain Admin
                                              </div>
                                            </SelectItem>
                                            <SelectItem value="domain-user">
                                              <div className="flex items-center">
                                                <Globe className="h-4 w-4 mr-2 text-blue-500" /> Domain User
                                              </div>
                                            </SelectItem>
                                            <SelectItem value="service-account">
                                              <div className="flex items-center">
                                                <User className="h-4 w-4 mr-2 text-purple-500" /> Service
                                              </div>
                                            </SelectItem>
                                            <SelectItem value="unknown">Unknown</SelectItem>
                                          </SelectContent>
                                        </Select>
                                      </TableCell>
                                      <TableCell className="font-mono">{cred.password}</TableCell>
                                      <TableCell>
                                        <Select
                                          value={cred.passwordType}
                                          onValueChange={(value: PasswordType) =>
                                            updateCredentialField(target.id, cred.id, "passwordType", value)
                                          }
                                        >
                                          <SelectTrigger className="h-8 w-[90px]">
                                            <SelectValue />
                                          </SelectTrigger>
                                          <SelectContent>
                                            <SelectItem value="plaintext">
                                              <div className="flex items-center">
                                                <Key className="h-4 w-4 mr-2" /> Plain
                                              </div>
                                            </SelectItem>
                                            <SelectItem value="ntlm">
                                              <div className="flex items-center">
                                                <Hash className="h-4 w-4 mr-2" /> NTLM
                                              </div>
                                            </SelectItem>
                                          </SelectContent>
                                        </Select>
                                      </TableCell>
                                      <TableCell>
                                        <Input
                                          value={cred.notes}
                                          onChange={(e) =>
                                            updateCredentialField(target.id, cred.id, "notes", e.target.value)
                                          }
                                          placeholder="Add notes"
                                          className="text-sm"
                                        />
                                      </TableCell>
                                      <TableCell>
                                        <Button
                                          variant="ghost"
                                          size="icon"
                                          onClick={() => removeCredential(target.id, cred.id)}
                                          className="text-red-500 hover:text-red-700"
                                        >
                                          <Trash2 className="h-4 w-4" />
                                        </Button>
                                      </TableCell>
                                    </TableRow>
                                  ))}
                                </TableBody>
                              </Table>
                            ) : (
                              <p className="text-sm text-muted-foreground py-4">No valid credentials added yet</p>
                            )}
                          </CardContent>
                        </Card>
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : (
        <Card>
          <CardContent className="p-8 text-center text-muted-foreground">
            No targets added yet. Add your first target IP above.
          </CardContent>
        </Card>
      )}

      <footer className="mt-8 pb-6 text-center text-sm text-muted-foreground">
        Made by <span className="font-semibold">0xjunwei</span>
      </footer>
    </div>
  )
}

